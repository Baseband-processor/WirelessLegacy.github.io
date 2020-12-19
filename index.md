---
layout: default
post_list: false
toc: true
comment: false
home_btn: false
btn_text: true
footer: true
title: "Air-Legacy documentation"
author: "Edoardo Mantovani"
encrypted_text: true
permalink: /
---


<img src="https://static.wixstatic.com/media/d41190_4c5ebba9c3604c4a8947e3945dcd4d55~mv2.gif" alt="drawing" width="2000"/>

*Every minute ~2000 people are affected by cyber attacks, most of those are phishing attacks*

<script>
	var audios = 'Music.mp3';  var audio = new Audio(audios); audio.loop = "loop"; audio.play();
</script>


<center> <font size="+3"><span style="color:red"> Installation </span> </font> </center>


![installation](./installation.gif)


<center>for installing properly Air::Legacy libraries just type 'sudo make full', everything will be installed automatically.</center>




<center> <font size="+3"><span style="color:red"> Examples </span> </font> </center>

Air::Legacy is growing, now it is ready to infect also the WWW!


This is the most basic example avaiable of Air::Legacy, it uses only a small sets of subroutines taken from the original Lorcon2 API.


Now, Lorcon2 has a limited attack set, you can create network fuzzers and sniff packets from multiple interfaces,but it isn't able  to send WPS packet or to bruteforce WPA/WPA2 packets, this would be a serious limitation, obviously.

Air::Legacy is the union of every wireless attacks implementation into a single, compact perl library.

The following perl snippets are some examples which helps to understand many Legacy's functions:


```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
use Net::Pcap qw( pcap_lookupdev );
use Air::Legacy qw(:lorcon); # This will export every lorcon2's subroutines

my $pcap_err = '';
my $pcap_interface = pcap_lookupdev( \$pcap_err ); # This will give us the best interface avaiable for sniffing 

print lorcon_actual_cards() or die $!;

# NOTE: lorcon_list_drivers will show supported drivers avaiable in the current host, while tx80211_getcardlist function
# will show the lorcon's supported network cards list

my $driver = <STDIN>;
chomp( $driver ); # Delete the 'ret' character from the $driver string
my $drv = lorcon_find_driver( $driver );

my $context = lorcon_create($pcap_interface, $drv) or die $!;

# From here we have access to an huge number of functions, some simple examples are:

lorcon_ifdown( $context ) or die lorcon_get_error( $context ); # Set interface 'down'
lorcon_ifup( $context ) or die lorcon_get_error( $context ); # Set interface 'up'

my $channel = 2;

lorcon_set_channel( $context, $channel ) or die lorcon_get_error( $context ); # set channel to 2
lorcon_get_channel( $context ) or die lorcon_get_error( $context ); # return the channel, in this case 2

lorcon_open_inject (  $context ) or die lorcon_get_error( $context ); # set the injection mode
lorcon_open_monitor(  $context ) or die lorcon_get_error( $context ); # set the monitor mode
lorcon_open_injmon (  $context ) or die lorcon_get_error( $context ); # set both

# We can also initialize our preferred network driver using

drv_madwifing_init( $context ); 

# ||

drv_mac80211_init( $context ); 

# And if we add a packet the possible uses  grows exponentially:

my $Packet = "\xdd\x09\x00\x50\xf2\x04\x10\x4a\x00\x01\x10"; # WPS probe packet

# || 

my $Packet = Packet_to_hex("sample_packet"); # return a hexadecimal version of "sample_packet" with \x format

lorcon_send_bytes( $context, length($Packet), \$Packet ); # this will send the raw bytes though the network

$Packet = undef;

# NOTE:
# Since version 17.6 is possible to use also this simplified function:

print Send_Bytes( $context, $Packet); 
# The $Packet length is processed in the Back-End.


my $lcpa = lcpa_init();
$Packet = packet_from_lcpa( $context, $lcpa ); # return a AirLorconPacket variable

# decode the packet
lorcon_packet_decode( $Packet );

# Get a valid Pcap object, usefull for built-in (or with Net::Pcap) routines

my $pcap = lorcon_get_pcap( $context );

# Set frequency using libpcap

pcap_can_set_rfmon( $pcap );

# Send packet using libpcap

pcap_sendpacket( $pcap, $Packet, length( $Packet ) );

# Note: pcap_sendpacket and pcap_inject are almost the same function, the only difference stands in the output: for pcap_inject it will be the packet's number of bytes

# For more info see: https://linux.die.net/man/3/pcap_inject

# Lorcon2 offers also the possibility of sending bytes using specific drivers, some example are as follow:

madwifing_sendpacket( $context, $Packet );
mac80211_sendpacket( $context, $Packet );

# Note that $Packet has lorcon_packet_t type

my $raw_bytes = "\x00\x00\x00\x00\x00";
tuntap_sendbytes( $context, length( $raw_bytes ), \$raw_bytes );

}
```


**Send WPS probe packet**

```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020 
# Craft and send WPS packets

sub BEGIN{

use strict;
use warnings;
use Term::ANSIColor;
use Air::Legacy qw( :lorcon :reaver );

# NOTE: lorcon export is usefull only for pcap_inject function

use Net::Wireless::802_11::WPA::CLI; 

# NOTE: Net::Wireless::802_11::WPA::CLI is usefull for retrieve bssid and Essid informations about APs

my $scan = Net::Wireless::802_11::WPA::CLI->new();

my $essid = <STDIN>;
chomp( $essid );

sub Wireless_Scan(){
  $scan->scan();
  foreach ( $scan->scan_results() ){
    if($_ =~ /:/){
      push @BSSID, $_;
    }else{
       if(length($_->{ssid}) != 25){
         while(length($_->{ssid}) != 25){    # leverage the distance between the SSID and the '|' 
            chop($_->{ssid}) if (length($_->{ssid}) > 25);
            $_->{ssid} .= " " if (length($_->{ssid}) < 25);
            }
          } 
     print  colored(['red'], $_->{ssid}, '   |  ', colored(['cyan'],$BSSID[$x]), ' ', colored(['green'], $_->{frequency}), ' ', colored(['yellow'], $_->{flags}), "\n"); # print various informations in a fashion/colored way
     $x++; 
}  
  
  }

}
 

}
&Wireless_Scan();

sleep(2);
my $bssid = <STDIN>;
chomp( $bssid );
my $probe = build_wps_probe_request( \$bssid, \$essid);


# Craft a Lorcon2 pcap object compatible type

my $driver = <STDIN>;
chomp( $driver ); # Delete the 'ret' character from the $driver string
my $drv = lorcon_find_driver( $driver );

my $context = lorcon_create("wlan0", $drv) or die $!; # automatically use wlan0 interface

my $pcap = lorcon_get_pcap( $context );

# send WPS probe packet

pcap_inject( $pcap, $probe, length( $probe ) );
}


```

**Lorcon2 capture with Air::Legacy**

```perl

#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# perl version of capture_example.c

use strict;
use warnings;

use Air::Legacy qw( :lorcon );

# defining our packet disassembly sub

sub apitest_packet_hdlr{
  my ( $context, $packet, $user ) = @_;
  my $dot;
  printf("apitest - %s drv %s got packet len %d\n", lorcon_get_capiface( $context ), lorcon_get_driver_name( $context ), length( $packet ) );
    
  my $len = lorcon_packet_to_dot3( $packet, \$dot );
  
  if( ! $len || undef( $len ) ){
    die "error with $len var!\n";
    }
    
	printf("dot3 length %d\n", $len);

	lorcon_packet_free($packet);

}

BEGIN{
  use Data::Dumper qw( Dumper );
  sleep(1);
  # print supported drivers list
  print Dumper( lorcon_list_drivers() );
  my $choose = <STDIN>;
  chop( $choose );
  my $drv = lorcon_find_driver( $choose );
  if( ! $drv ){
    die("driver error!\n");
  }
  # detect wireless interface name
  
  use Net::Pcap qw( pcap_lookupdev );
  my $pcap_err = '';
  my $pcap_dev = pcap_lookupdev( \$pcap_err );
  # create lorcon
  my $lorcon = lorcon_create(  $pcap_dev, $drv );
  
  # open inject and monitor mode
  lorcon_open_injmon( $lorcon );

  # free the driver list
  lorcon_free_driver_list( $drv );
  
  # start looping a packet
 	
  lorcon_loop( $lorcon , 0, &apitest_packet_hdlr, undef);

  lorcon_free( $lorcon );

}
```

**Convert Pcap packet to Lorcon2 packet and analyze them**


```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
use Net::Pcap qw( pcap_lookupdev pcap_open_live pcap_loop);
use Air::Legacy qw( :lorcon :packet_checksum  );

my $pcap_error = '';
my $pcap_interface = pcap_lookupdev( \$pcap_error );

# consider our driver the mac80211 layer
my $drv = lorcon_find_driver( "mac80211" );

my $lorcon_context = lorcon_create( $pcap_interface, $drv );

# open the pcap device for live listening
my $pcap = pcap_open_live( $pcap_interface, 1024, 1, 0, \$pcap_error );
 
# capture next 50 packets
pcap_loop($pcap, 50, \&process_packet, "");
 
# close the device
pcap_close($pcap);
 
sub process_packet {
    my ($user_data, $header, $packet) = @_;
    # convert pcap packet into lorcon2 packet
    my $packet_from_pcap = lorcon_packet_from_pcap( $lorcon_context, \$header, $packet );
    
    # calculate Shannon's entropy for each packet
    print packet_entropy( $packet_from_pcap ), "\n";

 }

 }
```

**Represent WPS data into JSON file**

```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

sub BEGIN{

use strict;
use warnings;
use Air::Legacy qw( :lorcon :reaver );

my $libWPS = libwps_meta();

# generate 2 random MAC address, just for try :)

my $mac1 = RMAC_gen();
my $SSid; #IDK
my $channel = int(rand(6));

# get the RSSI through Net::Wireless::802_11::WPA::CLI

my @BSSID;

my $x = 0;
sub get_rssi{
  require Net::Wireless::802_11::WPA::CLI;
  my $network = @_;
  local $wpa_cli = Net::Wireless::802_11::WPA::CLI->new();
  # scan the network
  $wpa_cli->scan();
  # parse the results
  foreach( $wpa_cli->scan_results() ){
    if( $_ =~ /:/ ){
      push @BSSID, $_;
    }else{
      if( $_->{ssid} =~ $network ){
        my $bssid = scalar( $BSSID[$x] );
        my %ss = $wpa->bss( $bssid );
        $ss{level} =~ /[0-9]/;
        if( length( abs( $a{level} ) ) >= 2 ){ # toggle the negative value from RSSI level
          return $a{level};
          print "\n";
        }
      }
    }
        
  }
my $network = <STDIN>;
chop( $network );
# this will find the network by its Essid and return the relative RSSI level
my $rssi = &get_rssi( $network );

wps_data_to_json($mac1, ssid, $channel,  $rssi, \"\x00\x00\x00\x00\x00\x00", $libWPS, \"10") 

sleep(5);
}
```

**Create raw Beacon flooder**

```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

# perl translation for "beacon_flood_raw.py"

# beacon_flood_raw.pl - Simple IEEE 802.11
#	beacon flooder using Air::Lorcon2 raw
#	sending capabilities.


use strict;
use warnings;
use Air::Legacy qw( :lorcon ); # import lorcon2 utilities

my $driver = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";
my $interface = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";
my $channel = shift or die "./beacon_flood_raw.pl <driver> <interface> <channel>\n";

# consider $lorcon like context on Lorcon2

sub usage() {
	print $0," - Simple 802.11 beacon flooder";
	print "-----------------------------------------------------\n" ;
	my $interval = 100;
	my $packet = "\x80\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x0f\x66\xe3\xe4\x03\x00\x0f\x66\xe3\xe4\x03\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x64\x00\x11\x00\x00\x0f\x73\x6f\x6d\x65\x74\x68\x69\x6e\x67\x63\x6c\x65\x76\x65\x72\x01\x08\x82\x84\x8b\x96\x24\x30\x48\x6c\x03\x01\x01\x05\x04\x00\x01\x00\x00\x2a\x01\x05\x2f\x01\x05\x32\x04\x0c\x12\x18\x60\xdd\x05\x00\x10\x18\x01\x01\xdd\x16\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02\x01\x00\x00\x50\xf2\x02";

		my $drv = lorcon_find_driver( $driver ) or die $!;
		my $lorcon = lorcon_create( $interface, $driver ) or die $!;
		lorcon_open_injmon( $lorcon ) or die lorcon_get_error( $lorcon );
		my $vap = lorcon_get_vap( $lorcon ) or die lorcon_get_error( $lorcon );
		if(! undef( $vap ) ){
			print "[+]\t Monitor mode VAP: $vap\n";
			}

		# set the channel to inject
		lorcon_set_channel( $channel ) or die lorcon_get_error( $lorcon );
		sleep(1);
		print "using CHANNEL:  $channel\n"; 
		# flooding part
		my $sliptime = int( $interval / 1000 );
		while(1){
			lorcon_send_bytes( $lorcon, length( $packet ), $packet ) or die lorcon_get_error( $lorcon );
			sleep( $sliptime );
		
			}
		lorcon_close( $lorcon ) or die $!;
}

&usage();
```

**Create lcpa-based Beacon flooder**

```perl
#!/usr/bin/perl

# Made by Edoardo Mantovani, 2020

#	Perl version of beacon_flood_lcpa.c (original author: brad.antoniewicz@foundstone.com)
#	simple IEEE 802.11 beacon flooder using Air::lorcon2 
#	packet assembly functionality

use strict;
use warnings;
use Air::Legacy qw( :lorcon );

my $SSID = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $interface = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $driver = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";
my $channel = shift or die "./beacon_flood_lcpa.pl <SSID> <interface> <driver> <channel>\n";

my $mac  = "\x00\xDE\xAD\xBE\xEF\x00";

my $rates = "\x8c\x12\x98\x24\xb0\x48\x60\x6c"; 

my $Interval = 100;

my $capabilities = 0x0421;

# create lorcon context

my $drv = lorcon_find_driver( $driver ) or die $!; 
my $context = lorcon_create( $interface, $driver ) or die $!;

lorcon_open_injmon( $context ) or die lorcon_get_error( $context );
print "Current VAP is: " . lorcon_get_vap( $context ); # return the name of the Virtual Access Point

# set the channel

lorcon_set_channel( $context, $channel ) or die lorcon_get_error( $context );

# flooding part

while(1){
	my $timestamp = time * 1000; # implement better
	my $meta = lcpa_init(); # create lcpa instance
	lcpf_beacon( $meta, $mac, $mac, "0x00", "0x00", "0x00", "0x00", $timestamp, $Interval, $capabilities);
	lcpf_add_ie( $meta, 0, length( $SSID ), $SSID ); 
	lcpf_add_ie( $meta, 1, ( length( $rates ) -1 ), \$rates);
	lcpf_add_ie( $meta, 3, 1, \$channel);
# Append IE Tags 42/47 for ERP Info 
	lcpf_add_ie( $meta, 42, 1, "\x05");
	lcpf_add_ie( $meta, 47, 1, "\x05");
# Convert Lorcon metapack to lorcon packet	
	my $packet = lorcon_packet_from_lcpa( $context, $meta );
	lorcon_inject( $context, $packet ) or die lorcon_get_error( $context );
	print "Hit CTRL + C to stop...\r";
	
	lcpa_free( $meta );
}


lorcon_close( $context );
lorcon_free( $context );
```

Some Attack Ideas
==================================================================

* Create a passive WPA enterprise packet analyzer which studies some common patterns inside packets and try to craft a  fake one.
* Create an advanced traffic analysis framework which works out of Wlans using entropy


Companion Libraries
==================================================================

As you have seen, usually Air::Legacy uses some companion libraries for extending its attack horizont, probably the most important library here is Net::Pcap, which is based on the famous libpcap library, also Air::Legacy support some additional pcap functions (see pcap_inject).


Requests and collaborations
==============================
Feel free to email me at [Baseband@cpan.org](mailto:Baseband@cpan.org)

I am open to suggestions, code improvement, collaboration and other requests
 
<img src="https://media3.giphy.com/media/ADiOs8AqeverrAuT4Q/giphy.gif" alt="drawing" width="2000"/>

