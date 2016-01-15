# Surf Advanced Proxy Project Docoument

# Technology #
iOS9+ Network extension framework
### Other Technology ###
* lwip 	integrated use C language
* Core code use  Swift language
* C/OC 3part lib: openssl,libsodium,RR libev port
* Swift 3part lib: SwiftJson,MMDB-Swift

###user features and imp####

* support User-Agent base rule 
* dns server 指定，如果没有使用system resolv
* /etc/host类似 支持，访问私有服务iOS
* ~~rule ip/mask，ProxyName/Reject/Random~~
* ~~hostnmame ProxyName/Reject/Random 域名远端解析~~ 
* ~~rule keyword 支持~~
* ~~proxy 多个支持，支持随机，测试方便~~
* udp 转发支持，如果有RR 
* udp 直连支持？dstPort >= 16384 &&  dstPort <= 16386
* ~~tcp/http(s) proxy处理~~
* connector：TT，http，socks5，direct
* ~~log view，log send~~
* rule 测试结果,测试结果显示
* 最近链接,designd, todo turning 
* china ip
* ~~rule drop 关ad~~
* dns cache？
* ~~config use json~~ 
* ~~build upload iTunesconnect(101,102) 2016/1/14~~
### todo list ####
*  ~~config file generate, opensource~~
*  ~~CONNECT mode implement 0105~~
*  ~~http -> direct~~
*  ~~https -> direct (0105,tested)~~
*  ~~http -> direct (tcp,don't need')~~
*  lwip tcp_write write check error need fix
*  http over TT (http)
*  https over TT (https)
*  http over http (http)
*  https over http (https)
*  http over socks5 (http)
*  https over socks5 (https)
*  ~~tcp -> direct (http )~~
*  tcp -> direct (https,test failure )
*  tcp -> direct (tcp,test)
*  tcp -> direct (tcp ssl,test)
*  tcp over TT
*  tcp over http(s)
*  tcp over socks5
