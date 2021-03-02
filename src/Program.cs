using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Linq;

namespace socks5
{
    static class Program
    {
        private static readonly string domain = "google.com";   

        static async Task Main(string[] args)
        {
            using var client = new TcpClient();
            
            await client.ProxyConnectAsync(
                proxyAddress: "3.239.96.8",
                proxyPort: 1080,
                destinationAddress: domain,
                destinationPort: 80);

            using var stream = client.GetStream();                
            var writer = new StreamWriter(stream);
                    
            writer.Write($"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n");

            using var reader = new StreamReader(stream);
                var i = 0;
                        
            while (true)
            {

                var line = reader.ReadLine();
                if (string.IsNullOrEmpty(line))
                {
                    i++;
                    Console.WriteLine(i); 

                    if (i > 3) {
                        break;  
                    }
                }

                Console.WriteLine(line);
            }   
        }

        public static async Task<TcpClient> ProxyConnectAsync(
            this TcpClient client,
            string proxyAddress,
            int proxyPort,
            string destinationAddress,
            int destinationPort,
            string username = null,
            string password = null)
        {
            await client.ConnectAsync(proxyAddress, proxyPort);
            var stream = client.GetStream();

            // RFC 1928
            // negotiate authentication
            // +-----+----------+----------+
            // | VER | NMETHODS | METHODS  |
            // +-----+----------+----------+
            // | 1   | 1        | 1 to 255 |
            // +-----+----------+----------+
            var auth = new byte[4];
            auth[0] = 0x05; // Version
            auth[1] = 0x01; // 1 methods

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                auth[2] = 0x02; // username and password
            }
            else
            {
                auth[2] = 0x00; // No auth-method
            }

            Console.WriteLine($"Sending auth handshake");
            await stream.WriteInternalAsync(auth, CancellationToken.None);

            // read the auth response
            // +-----+-------+
            // | VER | CAUTH |
            // +-----+-------+
            // | 1   | 1     |
            // +-----+-------+
            Console.WriteLine($"Reading auth response");
            var authResponse = await stream.ReadInternalAsync(2, CancellationToken.None);

            if (authResponse[0] != 0x05)
            {
                // ensure the server responds with the expected version (5)
                throw new IOException("Invalid Socks Version");
            }

            switch (authResponse[1])
            {
                case 0x00:
                    Console.WriteLine($"Server selected no-auth");
                    break;
                case 0x02:
                    Console.WriteLine($"Server selected username/password");
                    // RFC 1929
                    // +-----+------+----------+------+----------+
                    // | VER | ULEN | UNAME    | PLEN | PASSWD   |
                    // +-----+------+----------+------+----------+
                    // | 1   | 1    | 1 to 255 | 1    | 1 to 255 |
                    // +-----+------+----------+------+----------+
                    // write username/password

                    // read response
                    // +----+--------+
                    // |VER | STATUS |
                    // +----+--------+
                    // | 1  |   1    |
                    // +----+--------+
                    // 0x00 = success
                    // !0x00 = failure

                    break;
                case 0xff:
                    Console.WriteLine($"No acceptable auth methods");
                    break;
                default:
                    throw new Exception($"Unknown CAUTH response from server: {authResponse[1]}");
            }

            // Request the downstream connection
            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            // var domainBytes = Encoding.ASCII.GetBytes(destinationAddress);
            // var portBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)destinationPort));

            // var connectionRequest = new byte[7 + destinationAddress.Length];
            // connectionRequest[0] = 0x05; // Version
            // connectionRequest[1] = 0x01; // Connect (TCP)
            // connectionRequest[2] = 0x00; // Reserved
            // connectionRequest[3] = 0x03; // Dest.Addr: Domain name
            // connectionRequest[4] = (byte)destinationAddress.Length; // Domain name length (octet)

            // Array.Copy(domainBytes, 0, connectionRequest, 5, destinationAddress.Length); // DST.ADDR

            // connectionRequest[5 + destinationAddress.Length] = portBytes[0]; // DST.PORT[0]
            // connectionRequest[6 + destinationAddress.Length] = portBytes[1]; // DST.PORT[1]
            var buf = new byte[300];

            buf[0] = 0x05; // Version
            buf[1] = 0x01; // Connect (TCP)
            buf[2] = 0x00; // Reserved
            buf[3] = 0x03; // Dest.Addr: Domain name
            var domain = Encoding.ASCII.GetBytes("google.com");
            buf[4] = (byte)domain.Length; // Domain name length (octet)
            Array.Copy(domain, 0, buf, 5, domain.Length);
            var port = BitConverter.GetBytes(
                IPAddress.HostToNetworkOrder((short)80));
            buf[5 + domain.Length] = port[0];
            buf[6 + domain.Length] = port[1];
            
            Console.WriteLine($"Sending connection request");
            stream.Write(buf, 0, domain.Length + 7);

            //await stream.WriteInternalAsync(connectionRequest, CancellationToken.None);

            // read the connection response
            // +-----+-----+-------+------+----------+----------+
            // | VER | REP | RSV   | ATYP | BND.ADDR | BND.PORT |
            // +-----+-----+-------+------+----------+----------+
            // | 1   | 1   | X'00' | 1    | Variable | 2        |
            // +-----+-----+-------+------+----------+----------+
            Console.WriteLine($"Reading connection response");
            var connectionResponse = await stream.ReadInternalAsync(4, CancellationToken.None);

            if (connectionResponse[0] != 0x05) // VER/version
            {
                throw new IOException("Invalid Socks Version");
            }
            if (connectionResponse[1] != 0x00) // REP/reply
            {
                string msg = (connectionResponse[1]) switch
                {
                    0x01 => "General SOCKS server failure",
                    0x02 => "Connection not allowed by ruleset",
                    0x03 => "Network unreachable",
                    0x04 => "Host unreachable",
                    0x05 => "Connection refused",
                    0x06 => "TTL expired",
                    0x07 => "Command not supported",
                    0x08 => "Address type not supported",
                    _ => $"Unknown SOCKS error {connectionResponse[1]}",
                };

                throw new IOException($"SOCKS connection failed: {msg}");
            }

            string boundAddress;
            ushort boundPort;

            switch (connectionResponse[3]) // ATYP/address type
            {
                case 0x01: // IPv4
                    var boundIPBytes = await stream.ReadInternalAsync(4, CancellationToken.None);
                    boundAddress = new IPAddress(BitConverter.ToUInt32(boundIPBytes, 0)).ToString();
                    break;
                case 0x03: // Domain name
                    var lengthBytes = await stream.ReadInternalAsync(1, CancellationToken.None);

                    if (lengthBytes[0] == 0xff)
                    {
                        throw new IOException("Invalid Domain Name");
                    }

                    var boundDomainBytes = await stream.ReadInternalAsync(lengthBytes[0], CancellationToken.None);
                    boundAddress = Encoding.ASCII.GetString(boundDomainBytes);
                    break;
                case 0x04: // IPv6
                    var boundIPv6Bytes = await stream.ReadInternalAsync(16, CancellationToken.None);
                    boundAddress = new IPAddress(boundIPv6Bytes).ToString();
                    break;
                default:
                    throw new IOException("Unknown SOCKS Address type");
            }

            var boundPortBytes = await stream.ReadInternalAsync(2, CancellationToken.None);
            boundPort = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(boundPortBytes, 0));

            Console.WriteLine($"SOCKS proxy successfully bound to {destinationAddress}:{destinationPort} via {boundAddress}:{boundPort}");
            return client;
        }

        private static async Task<byte[]> ReadInternalAsync(this NetworkStream stream, long length, CancellationToken cancellationToken)
        {
            await using var memoryStream = new MemoryStream();

            await stream.ReadInternalAsync(length, memoryStream, (c) => Task.CompletedTask, cancellationToken).ConfigureAwait(false);
            return memoryStream.ToArray();
        }

        private static async Task ReadInternalAsync(this NetworkStream stream, long length, Stream outputStream, Func<CancellationToken, Task> governor, CancellationToken cancellationToken)
        {
            var buffer = new byte[4096];
            long totalBytesRead = 0;

            try
            {
                while (totalBytesRead < length)
                {
                    await governor(cancellationToken).ConfigureAwait(false);

                    var bytesRemaining = length - totalBytesRead;
                    var bytesToRead = bytesRemaining >= buffer.Length ? buffer.Length : (int)bytesRemaining; // cast to int is safe because of the check against buffer length.

                    var bytesRead = await stream.ReadAsync(buffer, 0, bytesToRead, cancellationToken).ConfigureAwait(false);

                    if (bytesRead == 0)
                    {
                        throw new Exception("Remote connection closed");
                    }

                    totalBytesRead += bytesRead;

                    await outputStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                }

                await outputStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (ex is TimeoutException || ex is OperationCanceledException)
                {
                    throw;
                }

                throw new Exception($"Failed to read {length} bytes from: {ex.Message}", ex);
            }
        }

        private static async Task WriteInternalAsync(this NetworkStream stream, byte[] bytes, CancellationToken cancellationToken)
        {
            await using var memoryStream = new MemoryStream(bytes);

            await stream.WriteInternalAsync(bytes.Length, memoryStream, (c) => Task.CompletedTask, cancellationToken).ConfigureAwait(false);
        }

        private static async Task WriteInternalAsync(this NetworkStream stream, long length, Stream inputStream, Func<CancellationToken, Task> governor, CancellationToken cancellationToken)
        {
            var inputBuffer = new byte[4096];
            var totalBytesWritten = 0;

            try
            {
                while (totalBytesWritten < length)
                {
                    await governor(cancellationToken).ConfigureAwait(false);

                    var bytesRemaining = length - totalBytesWritten;

                    var bytesToRead = bytesRemaining >= inputBuffer.Length ? inputBuffer.Length : (int)bytesRemaining;
                    var bytesRead = await inputStream.ReadAsync(inputBuffer.AsMemory(0, bytesToRead), cancellationToken).ConfigureAwait(false);

                    Console.WriteLine($"Writing {bytesRead} bytes");
                    Console.WriteLine($"{BitConverter.ToString(inputBuffer.Take(bytesRead).ToArray())}");
                    await stream.WriteAsync(inputBuffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);

                    totalBytesWritten += bytesRead;
                }
            }
            catch (Exception ex)
            {
                if (ex is TimeoutException || ex is OperationCanceledException)
                {
                    throw;
                }

                throw new Exception($"Failed to write {length} bytes to: {ex.Message}", ex);
            }
        }
    }
}
