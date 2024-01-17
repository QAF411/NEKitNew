import Foundation

/**socks5的账号密码*/
public class socks5Auth: NSObject {
    public var host: String!
    public var port: Int!
    public var username: String!
    public var password: String!
    public var endtime:  TimeInterval!
}

public class SOCKS5AuthAdapterFactory: ServerAdapterFactory {
    let username: String
    let password: String
    let endtime:  TimeInterval
    
    public init(_ auth: socks5Auth) {
        self.username = auth.username
        self.password = auth.password
        self.endtime  = auth.endtime
        super.init(serverHost: auth.host, serverPort: auth.port)
    }

    override open func getAdapterFor(session: ConnectSession) -> AdapterSocket {
        let adapter = SOCKS5AuthAdapter(serverHost: serverHost, serverPort: serverPort, username: username, password: password, endtime: endtime)
        adapter.socket = RawSocketFactory.getRawSocket()
        return adapter
    }
}

class SOCKS5AuthAdapter: SOCKS5Adapter {
    let username: Data
    let password: Data
    let endtime:  TimeInterval
    var waitAuthResult: Bool = false
    

    public init(serverHost: String, serverPort: Int, username: String, password: String, endtime: TimeInterval) {
        
        // 纯数字--[https://blog.csdn.net/feelinghappy/article/details/120041611]
        func isNumeric(_ str: String) -> Bool {
            let numericCharacters = CharacterSet.decimalDigits
            return str.rangeOfCharacter(from: numericCharacters.inverted) == nil
        }
        
        if(isNumeric(username)) {
//            // 使用MemoryLayout.size(ofValue:)和Data(bytes:count:)的方式
//            var intData = Data(bytes: &intValue, count: MemoryLayout.size(ofValue: intValue))
//
//            // 使用NSNumber的dataRepresentation方法
//            let number = NSNumber(value: intValue)
//            let numberData = number.dataRepresentation
//
//            print("intData: \(intData as NSData)")
//            print("numberData: \(numberData as NSData)")
            
            var user = username
            // 使用MemoryLayout.size(ofValue:)和Data(bytes:count:)的方式
            let intData = Data(bytes: &user, count: MemoryLayout.size(ofValue: user))
            self.username =  intData
        } else {
            self.username =  username.data(using: .utf8)!
        }
        
        if(isNumeric(password)) {
            var pass = password
            let intData = Data(bytes: &pass, count: MemoryLayout.size(ofValue: pass))
            self.password =  intData
        } else {
            self.password = password.data(using: .utf8)!
        }
        self.endtime  = endtime
        super.init(serverHost: serverHost, serverPort: serverPort)
        self.helloData = Data([0x05, 0x01, 0x02])
    }
    
    override func didConnectWith(socket: RawTCPSocketProtocol) {
        super.didConnectWith(socket: socket)

        internalStatus = .connecting // 让它继续处于 .connection 的状态，这样可以在 super.didRead 时跳过数据处理
    }

    override func didRead(data: Data, from socket: RawTCPSocketProtocol) {
        super.didRead(data: data, from: socket)
        // 判断是否过期，过期就断开连接
        if endtime<Date().timeIntervalSince1970 {
            disconnect()
            exit(0)
        }
        if internalStatus == .connecting {
            if data.count != 2 { // 无论是协商认证，还是认证结果，返回字节都是 2
                disconnect()
                return
            }
            if waitAuthResult == false { // 连接成功，等待发送密码回去
                let handshake = [UInt8](data)
                if handshake[0] == 0x05 && handshake[1] == 0x02 {
                    var auth: [UInt8] = [0x01, UInt8(username.count)]
                    auth += [UInt8](username)
                    auth += [UInt8(password.count)]
                    auth += [UInt8](password)

                    write(data: Data(auth))

                    waitAuthResult = true
                    socket.readDataTo(length: 2)
                } else { // 协议失败,退出VPN
                    disconnect()
                    return
                }
            } else { // 返回了认证结果
                let authresult = [UInt8](data)
                if authresult[0] == 0x01 && authresult[1] == 0x00 {
                    // 认证成功，进入 SOCKS5Adapter.didRead 处理流程
                    internalStatus = .readingMethodResponse
                    self.didRead(data: Data(), from: socket)
                } else {
                    // 退出之前先进行保存退出原因，登录APP后就可以得知
                    disconnect()
                    exit(0)
                }
            }
            return
        }
    }
}
