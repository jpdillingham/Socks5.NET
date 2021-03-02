using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

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
                destinationPort: 80,
                "foo", "bar");

            using var stream = client.GetStream();                
            
            Console.WriteLine($"Writing web request");
            var req = Encoding.ASCII.GetBytes($"GET / HTTP/1.1\r\nHost: {domain}\r\n\r\n");
            await stream.WriteAsync(req, CancellationToken.None);

            using var reader = new StreamReader(stream);
                        
            while (true)
            {
                var line = reader.ReadLine();
                
                if (line == null)
                {
                    break;
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
            string password = null,
            CancellationToken? cancellationToken = null)
        {
            const byte SOCKS_5 = 0x05;
            
            const byte AUTH_ANONYMOUS = 0x00;
            const byte AUTH_USERNAMEPASSWORD = 0x02;

            const byte IPV4 = 0x01;
            const byte DOMAIN = 0x03;
            const byte IPV6 = 0x04;

            const byte ERROR = 0xFF;
            const byte EMPTY = 0x00;

            cancellationToken ??= CancellationToken.None;

            await client.ConnectAsync(proxyAddress, proxyPort, cancellationToken.Value);
            var stream = client.GetStream();

            // The client connects to the server, and sends a version identifier/method selection message:
            // +-----+----------+----------+
            // | VER | NMETHODS | METHODS  |
            // +-----+----------+----------+
            // | 1   | 1        | 1 to 255 |
            // +-----+----------+----------+
            var auth = new byte[] { SOCKS_5, 0x01, AUTH_ANONYMOUS };

            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                auth = new byte[] { SOCKS_5, 0x02, AUTH_ANONYMOUS, AUTH_USERNAMEPASSWORD };
            }
            
            await stream.WriteAsync(auth, CancellationToken.None);

            // The server selects from one of the methods given in METHODS, and sends a METHOD selection message:
            // +-----+-------+
            // | VER | CAUTH |
            // +-----+-------+
            // | 1   | 1     |
            // +-----+-------+
            var authResponse = await stream.ReadAsync(2, CancellationToken.None);

            if (authResponse[0] != SOCKS_5)
            {
                throw new IOException("Invalid Socks Version");
            }

            switch (authResponse[1])
            {
                case AUTH_ANONYMOUS:
                    break;
                case AUTH_USERNAMEPASSWORD:
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
                    throw new Exception($"No acceptable auth methods");
                default:
                    throw new Exception($"Unknown CAUTH response from server: {authResponse[1]}");
            }

            // The SOCKS request is formed as follows:
            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            var domainBytes = Encoding.ASCII.GetBytes(destinationAddress);
            var portBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)destinationPort));

            var connection = new byte[7 + destinationAddress.Length];
            connection[0] = 0x05; // Version
            connection[1] = 0x01; // Connect (TCP)
            connection[2] = 0x00; // Reserved
            connection[3] = 0x03; // Dest.Addr: Domain name
            connection[4] = (byte)destinationAddress.Length; // Domain name length (octet)

            Array.Copy(domainBytes, 0, connection, 5, destinationAddress.Length); // DST.ADDR

            connection[5 + destinationAddress.Length] = portBytes[0]; // DST.PORT[0]
            connection[6 + destinationAddress.Length] = portBytes[1]; // DST.PORT[1]

            await stream.WriteAsync(connection);

            // The SOCKS request information is sent by the client as soon as it has
            // established a connection to the SOCKS server, and completed the
            // authentication negotiations.  The server evaluates the request, and
            // returns a reply formed as follows:
            // +-----+-----+-------+------+----------+----------+
            // | VER | REP | RSV   | ATYP | BND.ADDR | BND.PORT |
            // +-----+-----+-------+------+----------+----------+
            // | 1   | 1   | X'00' | 1    | Variable | 2        |
            // +-----+-----+-------+------+----------+----------+
            var connectionResponse = await stream.ReadAsync(4, CancellationToken.None);

            if (connectionResponse[0] != SOCKS_5)
            {
                throw new IOException("Invalid Socks Version");
            }
            if (connectionResponse[1] != EMPTY)
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

            switch (connectionResponse[3])
            {
                case IPV4: // IPv4
                    var boundIPBytes = await stream.ReadAsync(4, CancellationToken.None);
                    boundAddress = new IPAddress(BitConverter.ToUInt32(boundIPBytes, 0)).ToString();
                    break;
                case DOMAIN: // Domain name
                    var lengthBytes = await stream.ReadAsync(1, CancellationToken.None);

                    if (lengthBytes[0] == ERROR)
                    {
                        throw new IOException("Invalid Domain Name");
                    }

                    var boundDomainBytes = await stream.ReadAsync(lengthBytes[0], CancellationToken.None);
                    boundAddress = Encoding.ASCII.GetString(boundDomainBytes);
                    break;
                case IPV6: // IPv6
                    var boundIPv6Bytes = await stream.ReadAsync(16, CancellationToken.None);
                    boundAddress = new IPAddress(boundIPv6Bytes).ToString();
                    break;
                default:
                    throw new IOException("Unknown SOCKS Address type");
            }

            var boundPortBytes = await stream.ReadAsync(2, CancellationToken.None);
            boundPort = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(boundPortBytes, 0));

            Console.WriteLine($"SOCKS proxy successfully bound to {destinationAddress}:{destinationPort} via {boundAddress}:{boundPort}");
            return client;
        }

        private static async Task<byte[]> ReadAsync(this NetworkStream stream, int length, CancellationToken cancellationToken)
        {
            var buffer = new byte[1024];
            var bytesRead = await stream.ReadAsync(buffer, 0, length, cancellationToken).ConfigureAwait(false);
            return buffer.AsSpan<byte>().Slice(0, bytesRead).ToArray();
        }
    }
}
