import Foundation

public class socks5Auth: NSObject {
    public var host: String!
    public var port: Int!
    public var username: String!
    public var password: String!
    public var endtime: TimeInterval!
}

public class SOCKS5AuthAdapterFactory: ServerAdapterFactory {
    let username: String
    let password: String
    let endtime: TimeInterval
    
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
    let endtime: TimeInterval
    var waitAuthResult: Bool = false
    
    init(serverHost: String, serverPort: Int, username: String, password: String, endtime: TimeInterval) {
        self.username = convertToData(username)
        self.password = convertToData(password)
        self.endtime  = endtime
        super.init(serverHost: serverHost, serverPort: serverPort)
        self.helloData = Data([0x05, 0x01, 0x02])
    }
    
    override func didConnectWith(socket: RawTCPSocketProtocol) {
        super.didConnectWith(socket: socket)
        internalStatus = .connecting
    }

    override func didRead(data: Data, from socket: RawTCPSocketProtocol) {
        super.didRead(data: data, from: socket)
        
        if endtime < Date().timeIntervalSince1970 {
            disconnect()
            // 考虑优雅地处理过期错误
            return
        }
        
        if internalStatus == .connecting {
            handleConnectingData(data)
        }
    }
    
    private func handleConnectingData(_ data: Data) {
        guard data.count == 2 else {
            disconnect()
            return
        }
        
        if waitAuthResult == false {
            handleConnectionSuccess()
        } else {
            handleAuthResult(data)
        }
    }
    
    private func handleConnectionSuccess() {
        let handshake = [UInt8](data)
        if handshake[0] == 0x05 && handshake[1] == 0x02 {
            sendAuthData()
            waitAuthResult = true
            socket.readDataTo(length: 2)
        } else {
            disconnect()
            // 优雅地处理协议失败
        }
    }
    
    private func handleAuthResult(_ data: Data) {
        let authResult = [UInt8](data)
        if authResult[0] == 0x01 && authResult[1] == 0x00 {
            internalStatus = .readingMethodResponse
            didRead(data: Data(), from: socket)
        } else {
            disconnect()
            // 优雅地处理身份验证失败
        }
    }
    
    private func sendAuthData() {
        write(data: username)
        write(data: password)
    }
    
    private func convertToData(_ input: String) -> Data {
        guard let numericValue = Int(input) else {
            return Data(input.utf8)
        }
        
        var intValue = numericValue
        return Data(bytes: &intValue, count: MemoryLayout.size(ofValue: intValue))
    }
}
