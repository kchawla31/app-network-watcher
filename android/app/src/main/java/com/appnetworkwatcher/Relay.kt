package com.appnetworkwatcher

import android.net.VpnService
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * IPv4 userspace relay. Intercepted TCP ports are sent to the desktop proxy.
 * Other TCP and UDP are forwarded with a socket that is protected from the VPN.
 * IPv6 and ICMP are not relayed.
 */
internal class Relay(
    private val input: FileInputStream,
    private val output: FileOutputStream,
    private val vpn: VpnService,
    private val proxyHost: String,
    private val proxyPort: Int,
) {
    private val running = AtomicBoolean(true)
    private val connections = ConcurrentHashMap<String, Conn>()
    private var loggedIpv6 = false
    private var loggedIcmp = false

    fun stop() {
        running.set(false)
        connections.values.forEach { it.close() }
        runCatching { input.close() }
    }

    fun loop() {
        val buffer = ByteArray(32767)
        while (running.get()) {
            val length = runCatching { input.read(buffer) }.getOrDefault(-1)
            if (length <= 0) {
                break
            }
            handle(buffer, length)
        }
    }

    private fun handle(buffer: ByteArray, length: Int) {
        if (length < 20) {
            return
        }
        val version = buffer[0].toInt() ushr 4
        if (version == 6) {
            if (!loggedIpv6) {
                Log.i(TAG, "IPv6 is not captured")
                loggedIpv6 = true
            }
            return
        }
        if (version != 4) {
            return
        }
        val headerLength = (buffer[0].toInt() and 0x0f) * 4
        if (headerLength < 20 || length < headerLength) {
            return
        }
        val protocol = buffer[9].toInt() and 0xff
        val src = buffer.copyOfRange(12, 16)
        val dst = buffer.copyOfRange(16, 20)
        when (protocol) {
            6 -> onTcp(buffer, length, headerLength, src, dst)
            17 -> onUdp(buffer, length, headerLength, src, dst)
            1 -> {
                if (!loggedIcmp) {
                    Log.i(TAG, "ICMP is not relayed")
                    loggedIcmp = true
                }
            }
        }
    }

    private fun onTcp(packet: ByteArray, length: Int, ipHeader: Int, src: ByteArray, dst: ByteArray) {
        if (length < ipHeader + 20) {
            return
        }
        val srcPort = u16(packet, ipHeader)
        val dstPort = u16(packet, ipHeader + 2)
        val seq = u32(packet, ipHeader + 4)
        val ack = u32(packet, ipHeader + 8)
        val dataOffset = ((packet[ipHeader + 12].toInt() ushr 4) and 0x0f) * 4
        val flags = packet[ipHeader + 13].toInt() and 0xff
        val payloadStart = ipHeader + dataOffset
        if (payloadStart > length) {
            return
        }
        val payload = packet.copyOfRange(payloadStart, length)
        val key = key(src, srcPort, dst, dstPort)
        val conn = connections.getOrPut(key) { Conn(src, srcPort, dst, dstPort) }
        if (flags and 0x02 != 0 && flags and 0x10 == 0) {
            conn.clientAck = seq + 1
            conn.ourSeq = (System.nanoTime() and 0xffffffffL)
            sendTcp(conn, 0x12, ByteArray(0))
            conn.ourSeq += 1
            if (!intercept(dstPort) || isProxy(dst, dstPort)) {
                openRaw(conn)
            }
            return
        }
        if (flags and 0x04 != 0 || flags and 0x01 != 0) {
            conn.clientAck = seq + 1
            sendTcp(conn, 0x11, ByteArray(0))
            conn.close()
            connections.remove(key)
            return
        }
        if (payload.isEmpty()) {
            return
        }
        if (seq != conn.clientAck) {
            sendTcp(conn, 0x10, ByteArray(0))
            return
        }
        conn.clientAck = seq + payload.size.toLong()
        sendTcp(conn, 0x10, ByteArray(0))
        if (conn.socket == null && intercept(dstPort) && !isProxy(dst, dstPort)) {
            conn.pending.write(payload)
            openIntercept(conn)
        } else if (conn.socket != null) {
            runCatching { conn.socket?.getOutputStream()?.write(payload) }
        } else {
            conn.pending.write(payload)
        }
    }

    private fun onUdp(packet: ByteArray, length: Int, ipHeader: Int, src: ByteArray, dst: ByteArray) {
        if (length < ipHeader + 8) {
            return
        }
        val srcPort = u16(packet, ipHeader)
        val dstPort = u16(packet, ipHeader + 2)
        val payload = packet.copyOfRange(ipHeader + 8, length)
        Thread {
            runCatching {
                val socket = DatagramSocket()
                vpn.protect(socket)
                socket.soTimeout = 4000
                val address = InetAddress.getByAddress(dst)
                socket.send(DatagramPacket(payload, payload.size, address, dstPort))
                val buffer = ByteArray(2048)
                val reply = DatagramPacket(buffer, buffer.size)
                socket.receive(reply)
                sendUdp(src, srcPort, dst, dstPort, buffer.copyOf(reply.length))
                socket.close()
            }
        }.start()
    }

    private fun openRaw(conn: Conn) {
        Thread {
            runCatching {
                val socket = Socket()
                vpn.protect(socket)
                socket.connect(InetSocketAddress(InetAddress.getByAddress(conn.dst), conn.dstPort), 8000)
                conn.socket = socket
                val pending = conn.pending.toByteArray()
                if (pending.isNotEmpty()) {
                    socket.getOutputStream().write(pending)
                    conn.pending.reset()
                }
                readRemote(conn, socket.getInputStream())
            }.onFailure {
                Log.i(TAG, "pass-through failed: ${it.message}")
                conn.close()
            }
        }.start()
    }

    private fun openIntercept(conn: Conn) {
        if (conn.opening) {
            return
        }
        val buffered = conn.pending.toByteArray()
        val host = sni(buffered) ?: httpHost(buffered) ?: inet(conn.dst)
        if (host == inet(conn.dst) && buffered.size < 64 && conn.dstPort == 443) {
            return
        }
        conn.opening = true
        Thread {
            runCatching {
                val socket = Socket()
                vpn.protect(socket)
                socket.connect(InetSocketAddress(proxyHost, proxyPort), 8000)
                if (conn.dstPort == 80) {
                    socket.getOutputStream().write(absoluteForm(buffered, host))
                } else {
                    val connect = "CONNECT $host:${conn.dstPort} HTTP/1.1\r\nHost: $host:${conn.dstPort}\r\n\r\n"
                    socket.getOutputStream().write(connect.toByteArray())
                    if (!readStatus(socket.getInputStream())) {
                        error("proxy refused CONNECT")
                    }
                    socket.getOutputStream().write(buffered)
                }
                conn.socket = socket
                conn.pending.reset()
                readRemote(conn, socket.getInputStream())
            }.onFailure {
                Log.i(TAG, "intercept failed for $host:${conn.dstPort}: ${it.message}")
                conn.close()
            }
        }.start()
    }

    private fun readRemote(conn: Conn, remote: InputStream) {
        val buffer = ByteArray(1200)
        while (running.get()) {
            val count = remote.read(buffer)
            if (count < 0) {
                break
            }
            if (count == 0) {
                continue
            }
            sendTcp(conn, 0x18, buffer.copyOf(count))
            conn.ourSeq += count
        }
        sendTcp(conn, 0x11, ByteArray(0))
        conn.ourSeq += 1
    }

    private fun sendTcp(conn: Conn, flags: Int, payload: ByteArray) {
        val tcpLength = 20 + payload.size
        val total = 20 + tcpLength
        val packet = ByteArray(total)
        packet[0] = 0x45
        packet[2] = (total ushr 8).toByte()
        packet[3] = total.toByte()
        packet[8] = 64
        packet[9] = 6
        conn.dst.copyInto(packet, 12)
        conn.src.copyInto(packet, 16)
        val ipSum = checksum(packet, 0, 20, null, null, 0)
        packet[10] = (ipSum ushr 8).toByte()
        packet[11] = ipSum.toByte()
        put16(packet, 20, conn.dstPort)
        put16(packet, 22, conn.srcPort)
        put32(packet, 24, conn.ourSeq)
        put32(packet, 28, conn.clientAck)
        packet[32] = (5 shl 4).toByte()
        packet[33] = flags.toByte()
        put16(packet, 34, 65535)
        payload.copyInto(packet, 40)
        val sum = checksum(packet, 20, tcpLength, conn.dst, conn.src, 6)
        put16(packet, 36, sum)
        synchronized(output) {
            output.write(packet)
        }
    }

    private fun sendUdp(
        src: ByteArray,
        srcPort: Int,
        dst: ByteArray,
        dstPort: Int,
        payload: ByteArray,
    ) {
        val udpLength = 8 + payload.size
        val total = 20 + udpLength
        val packet = ByteArray(total)
        packet[0] = 0x45
        packet[2] = (total ushr 8).toByte()
        packet[3] = total.toByte()
        packet[8] = 64
        packet[9] = 17
        dst.copyInto(packet, 12)
        src.copyInto(packet, 16)
        val ipSum = checksum(packet, 0, 20, null, null, 0)
        packet[10] = (ipSum ushr 8).toByte()
        packet[11] = ipSum.toByte()
        put16(packet, 20, dstPort)
        put16(packet, 22, srcPort)
        put16(packet, 24, udpLength)
        payload.copyInto(packet, 28)
        val sum = checksum(packet, 20, udpLength, dst, src, 17)
        put16(packet, 26, sum)
        synchronized(output) {
            output.write(packet)
        }
    }

    private fun intercept(port: Int): Boolean = port in INTERCEPT_PORTS

    private fun isProxy(dst: ByteArray, port: Int): Boolean {
        if (port != proxyPort) {
            return false
        }
        val address = runCatching { InetAddress.getByName(proxyHost).address }.getOrNull() ?: return false
        return address.contentEquals(dst)
    }

    private class Conn(
        val src: ByteArray,
        val srcPort: Int,
        val dst: ByteArray,
        val dstPort: Int,
    ) {
        var ourSeq: Long = 0
        var clientAck: Long = 0
        var socket: Socket? = null
        var opening: Boolean = false
        val pending = java.io.ByteArrayOutputStream()

        fun close() {
            runCatching { socket?.close() }
        }
    }

    companion object {
        private const val TAG = "WatcherVpn"
        private val INTERCEPT_PORTS = setOf(80, 443, 8000, 8001, 8080, 8888, 9000)

        private fun key(src: ByteArray, srcPort: Int, dst: ByteArray, dstPort: Int): String {
            return "${inet(src)}:$srcPort-${inet(dst)}:$dstPort"
        }

        private fun inet(bytes: ByteArray): String {
            return bytes.joinToString(".") { (it.toInt() and 0xff).toString() }
        }

        private fun u16(bytes: ByteArray, offset: Int): Int {
            return ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
        }

        private fun u32(bytes: ByteArray, offset: Int): Long {
            return ((bytes[offset].toLong() and 0xff) shl 24) or
                ((bytes[offset + 1].toLong() and 0xff) shl 16) or
                ((bytes[offset + 2].toLong() and 0xff) shl 8) or
                (bytes[offset + 3].toLong() and 0xff)
        }

        private fun put16(bytes: ByteArray, offset: Int, value: Int) {
            bytes[offset] = (value ushr 8).toByte()
            bytes[offset + 1] = value.toByte()
        }

        private fun put32(bytes: ByteArray, offset: Int, value: Long) {
            bytes[offset] = (value ushr 24).toByte()
            bytes[offset + 1] = (value ushr 16).toByte()
            bytes[offset + 2] = (value ushr 8).toByte()
            bytes[offset + 3] = value.toByte()
        }

        private fun checksum(
            packet: ByteArray,
            offset: Int,
            length: Int,
            src: ByteArray?,
            dst: ByteArray?,
            protocol: Int,
        ): Int {
            var sum = 0L
            if (src != null && dst != null) {
                sum += u16(src, 0).toLong() + u16(src, 2)
                sum += u16(dst, 0).toLong() + u16(dst, 2)
                sum += protocol.toLong()
                sum += length.toLong()
            }
            var index = offset
            val end = offset + length
            while (index + 1 < end) {
                sum += u16(packet, index).toLong()
                index += 2
            }
            if (index < end) {
                sum += (packet[index].toLong() and 0xff) shl 8
            }
            while (sum > 0xffff) {
                sum = (sum and 0xffff) + (sum ushr 16)
            }
            return (sum.toInt().inv()) and 0xffff
        }

        private fun sni(bytes: ByteArray): String? {
            if (bytes.size < 5 || bytes[0] != 0x16.toByte()) {
                return null
            }
            var index = 43
            if (bytes.size <= index) {
                return null
            }
            // Skip the record header (5), handshake header (4), version (2), random (32).
            index = 5 + 4 + 2 + 32
            if (index >= bytes.size) {
                return null
            }
            val sessionLength = bytes[index].toInt() and 0xff
            index += 1 + sessionLength
            if (index + 2 > bytes.size) {
                return null
            }
            val cipherLength = u16(bytes, index)
            index += 2 + cipherLength
            if (index >= bytes.size) {
                return null
            }
            val compressionLength = bytes[index].toInt() and 0xff
            index += 1 + compressionLength
            if (index + 2 > bytes.size) {
                return null
            }
            val extensionsLength = u16(bytes, index)
            index += 2
            val extensionsEnd = (index + extensionsLength).coerceAtMost(bytes.size)
            while (index + 4 <= extensionsEnd) {
                val type = u16(bytes, index)
                val size = u16(bytes, index + 2)
                index += 4
                if (index + size > bytes.size) {
                    return null
                }
                if (type == 0 && size >= 5) {
                    val nameLength = u16(bytes, index + 3)
                    val start = index + 5
                    if (start + nameLength <= bytes.size) {
                        return String(bytes, start, nameLength, Charsets.US_ASCII)
                    }
                }
                index += size
            }
            return null
        }

        private fun httpHost(bytes: ByteArray): String? {
            val text = runCatching { String(bytes, Charsets.ISO_8859_1) }.getOrNull() ?: return null
            val line = text.lineSequence().firstOrNull {
                it.startsWith("Host:", ignoreCase = true)
            } ?: return null
            return line.substringAfter(':').trim().substringBefore(':')
        }

        private fun absoluteForm(bytes: ByteArray, host: String): ByteArray {
            val text = String(bytes, Charsets.ISO_8859_1)
            val split = text.indexOf("\r\n")
            if (split < 0) {
                return bytes
            }
            val first = text.substring(0, split)
            val parts = first.split(' ')
            if (parts.size < 2 || parts[1].startsWith("http://")) {
                return bytes
            }
            val rewritten = "${parts[0]} http://$host${parts[1]} ${parts.getOrElse(2) { "HTTP/1.1" }}"
            return (rewritten + text.substring(split)).toByteArray(Charsets.ISO_8859_1)
        }

        private fun readStatus(input: InputStream): Boolean {
            val buffer = ByteArray(1024)
            val collected = java.io.ByteArrayOutputStream()
            while (collected.size() < 4096) {
                val count = input.read(buffer)
                if (count <= 0) {
                    return false
                }
                collected.write(buffer, 0, count)
                val text = collected.toString(Charsets.ISO_8859_1)
                if (text.contains("\r\n\r\n")) {
                    return text.startsWith("HTTP/1.1 200") || text.startsWith("HTTP/1.0 200")
                }
            }
            return false
        }
    }
}
