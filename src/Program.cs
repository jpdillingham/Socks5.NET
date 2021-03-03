using System;
using System.Collections.Generic;
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
        private static readonly string domain = "172.217.2.238";   

        static async Task Main(string[] args)
        {
            using var client = new TcpClient();
            
            var (addr, port) = await client.ProxyConnectAsync(
                proxyAddress: "10.8.0.1",
                proxyPort: 1080,
                destinationAddress: domain,
                destinationPort: 80,
                "foo", "bar");

            Console.WriteLine($"Proxy connected {addr}:{port}");

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

        public static async Task<(string ProxyAddress, int ProxyPort)> ProxyConnectAsync(
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

            const byte CONNECT = 0x01;

            const byte IPV4 = 0x01;
            const byte DOMAIN = 0x03;
            const byte IPV6 = 0x04;

            const byte EMPTY = 0x00;
            const byte ERROR = 0xFF;

            cancellationToken ??= CancellationToken.None;

            await client.ConnectAsync(proxyAddress, proxyPort, cancellationToken.Value);
            var stream = client.GetStream();

            // https://tools.ietf.org/html/rfc1928

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
            
            await stream.WriteAsync(auth, cancellationToken.Value);

            // The server selects from one of the methods given in METHODS, and sends a METHOD selection message:
            // +-----+--------+
            // | VER | METHOD |
            // +-----+--------+
            // | 1   | 1      |
            // +-----+--------+
            var authResponse = await stream.ReadAsync(2, cancellationToken.Value);

            if (authResponse[0] != SOCKS_5)
            {
                throw new IOException("Invalid Socks Version");
            }

            switch (authResponse[1])
            {
                case AUTH_ANONYMOUS:
                    break;
                case AUTH_USERNAMEPASSWORD:
                    // https://tools.ietf.org/html/rfc1929

                    // Once the SOCKS V5 server has started, and the client has selected the
                    // Username / Password Authentication protocol, the Username / Password
                    // subnegotiation begins.  This begins with the client producing a
                    // Username / Password request:
                    // +-----+------+----------+------+----------+
                    // | VER | ULEN | UNAME    | PLEN | PASSWD   |
                    // +-----+------+----------+------+----------+
                    // | 1   | 1    | 1 to 255 | 1    | 1 to 255 |
                    // +-----+------+----------+------+----------+
                    var creds = new List<byte>() { SOCKS_5 };

                    creds.Add((byte)username.Length);
                    creds.AddRange(Encoding.ASCII.GetBytes(username));

                    creds.Add((byte)password.Length);
                    creds.AddRange(Encoding.ASCII.GetBytes(password));

                    await stream.WriteAsync(creds.ToArray(), cancellationToken.Value);

                    // The server verifies the supplied UNAME and PASSWD, and sends the
                    // following response:
                    // +----+--------+
                    // |VER | STATUS |
                    // +----+--------+
                    // | 1  |   1    |
                    // +----+--------+
                    var credsResponse = await stream.ReadAsync(2, cancellationToken.Value);

                    if (credsResponse[0] != SOCKS_5)
                    {
                        throw new IOException("Invalid Socks Version");
                    }

                    if (credsResponse[1] != EMPTY)
                    {
                        throw new Exception("Authentication failed");
                    }

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
            var connection = new List<byte>() { SOCKS_5, CONNECT, EMPTY, DOMAIN };

            connection.Add((byte)destinationAddress.Length);
            connection.AddRange(Encoding.ASCII.GetBytes(destinationAddress));

            connection.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short)destinationPort)));

            await stream.WriteAsync(connection.ToArray(), cancellationToken.Value);

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
                case IPV4:
                    var boundIPBytes = await stream.ReadAsync(4, CancellationToken.None);
                    boundAddress = new IPAddress(BitConverter.ToUInt32(boundIPBytes, 0)).ToString();
                    break;
                case DOMAIN:
                    var lengthBytes = await stream.ReadAsync(1, CancellationToken.None);

                    if (lengthBytes[0] == ERROR)
                    {
                        throw new IOException("Invalid Domain Name");
                    }

                    var boundDomainBytes = await stream.ReadAsync(lengthBytes[0], CancellationToken.None);
                    boundAddress = Encoding.ASCII.GetString(boundDomainBytes);
                    break;
                case IPV6:
                    var boundIPv6Bytes = await stream.ReadAsync(16, CancellationToken.None);
                    boundAddress = new IPAddress(boundIPv6Bytes).ToString();
                    break;
                default:
                    throw new IOException("Unknown SOCKS Address type");
            }

            var boundPortBytes = await stream.ReadAsync(2, CancellationToken.None);
            boundPort = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(boundPortBytes, 0));

            return (boundAddress, boundPort);
        }

        private static async Task<byte[]> ReadAsync(this NetworkStream stream, int length, CancellationToken cancellationToken)
        {
            var buffer = new byte[1024];
            var bytesRead = await stream.ReadAsync(buffer, 0, length, cancellationToken).ConfigureAwait(false);
            return buffer.AsSpan<byte>().Slice(0, bytesRead).ToArray();
        }
    }
}
