using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace socks5
{
    static class Program
    {
        static void ReadAll(this NetworkStream stream, byte[] buffer, int offset, int size)
        {
            while (size != 0)
            {
                var read = stream.Read(buffer, offset, size);
                if (read < 0)
                {
                    throw new IOException("Premature end");
                }
                size -= read;
                offset += read;
            }
        }
        static void Main(string[] args)
        {
            using (var client = new TcpClient())
            {
                client.Connect("10.8.0.1", 1080); // Provide IP, Port yourself
                using (var stream = client.GetStream())
                {
                    // RFC 1928
                    // +-----+----------+----------+
                    // | VER | NMETHODS | METHODS  |
                    // +-----+----------+----------+
                    // | 1   | 1        | 1 to 255 |
                    // +-----+----------+----------+
                    var buf = new byte[300];
                    buf[0] = 0x05; // Version
                    buf[1] = 0x02; // 2 methods
                    buf[2] = 0x00; // No auth-method
                    buf[3] = 0x02; // username and password
                    stream.Write(buf, 0, 4);

                    // read the init/auth response
                    // +-----+-------+
                    // | VER | CAUTH |
                    // +-----+-------+
                    // | 1   | 1     |
                    // +-----+-------+
                    stream.ReadAll(buf, offset: 0, size: 2);
                    if (buf[0] != 0x05)
                    {
                        // ensure the server responds with the expected version (5)
                        throw new IOException("Invalid Socks Version");
                    }

                    switch (buf[1])
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
                            throw new Exception($"Unknown CAUTH response from server: {buf[1]}");
                    }

                    // +----+-----+-------+------+----------+----------+
                    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                    // +----+-----+-------+------+----------+----------+
                    // | 1  |  1  | X'00' |  1   | Variable |    2     |
                    // +----+-----+-------+------+----------+----------+

                    // Request the downstream connection
                    buf[0] = 0x05; // Version
                    buf[1] = 0x01; // Connect (TCP)
                    buf[2] = 0x00; // Reserved
                    buf[3] = 0x03; // Dest.Addr: Domain name

                    var domain = Encoding.ASCII.GetBytes("whatnet.us");
                    buf[4] = (byte)domain.Length; // Domain name length (octet)
                    Array.Copy(domain, 0, buf, 5, domain.Length);
                    var port = BitConverter.GetBytes(
                      IPAddress.HostToNetworkOrder((short)80));
                    buf[5 + domain.Length] = port[0];
                    buf[6 + domain.Length] = port[1];
                    stream.Write(buf, 0, domain.Length + 7);

                    // read the connection response
                    stream.ReadAll(buf, offset: 0, size: 4);
                    if (buf[0] != 0x05)
                    {
                        throw new IOException("Invalid Socks Version");
                    }
                    if (buf[1] != 0x00)
                    {
                        throw new IOException(string.Format("Socks Error {0:X}", buf[1]));
                    }


                    var rdest = string.Empty;
                    switch (buf[3])
                    {
                        case 0x01: // IPv4
                            stream.ReadAll(buf, 0, 4);
                            var v4 = BitConverter.ToUInt32(buf, 0);
                            rdest = new IPAddress(v4).ToString();
                            break;
                        case 0x03: // Domain name
                            stream.ReadAll(buf, 0, 1);
                            if (buf[0] == 0xff)
                            {
                                throw new IOException("Invalid Domain Name");
                            }
                            stream.ReadAll(buf, 1, buf[0]);
                            rdest = Encoding.ASCII.GetString(buf, 1, buf[0]);
                            break;
                        case 0x04: // IPv6
                            var octets = new byte[16];
                            stream.ReadAll(octets, 0, 16);
                            rdest = new IPAddress(octets).ToString();
                            break;
                        default:
                            throw new IOException("Invalid Address type");
                    }
                    stream.ReadAll(buf, 0, 2);
                    var rport = (ushort)IPAddress.NetworkToHostOrder((short)BitConverter.ToUInt16(buf, 0));
                    Console.WriteLine("Connected via {0}:{1}", rdest, rport);

                    // Make an HTTP request, aka. "do stuff ..."
                    using (var writer = new StreamWriter(stream))
                    {
                        writer.Write("GET / HTTP/1.1\r\nHost: whatnet.us\r\n\r\n");
                        writer.Flush();

                        using (var reader = new StreamReader(stream))
                        {
                            while (true)
                            {
                                var line = reader.ReadLine();
                                if (string.IsNullOrEmpty(line))
                                {
                                    break;
                                }

                                Console.WriteLine(line);
                            }
                        }
                    }
                }
            }
        }
    }
}
