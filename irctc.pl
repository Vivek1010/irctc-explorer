
use strict;
use Crypt::MatrixSSL;
use IO::Socket;
use IO::Socket::INET;
use Socket;
use IO::Select;


my $loop = 7;

my $readset = IO::Select->new();
my $writeset = IO::Select->new();
my $readable;
my $writeable;

my $count;

my %s;
my %in;
my %out;
my %sslstate;
my %socketstate;
my %httpstate;
#my %state;
my %times;
my %sslin;
my %sslout;
my %handshakestate;

#MatrixSSL
my $keys;
my %ssl;
my %sessionid;
my %sslout;
my %sslin;
my %sslhandshakecomplete;
my %hosts = (	1 => 'www.irctc.co.in:443',
				2 => 'www.irctc.co.in:443',
				3 => 'www.irctc.co.in:443',
				4 => 'www.irctc.co.in:443',
				5 => 'www.irctc.co.in:443',
				6 => 'www.irctc.co.in:443',
				7 => 'www.irctc.co.in:443',
				8 => 'www.irctc.co.in:443',
				9 => 'www.citibank.co.in:443',
				10 => 'cardsecurity.enstage.com:443'
			)


my %requests;


# Create sockets

sub create_socket_irctc
{
    my $count = $_[0];
    do
    {
        $s{$count} = IO::Socket::INET->new(PeerAddr=>$hosts{$count},Blocking=>0,Proto=>'tcp';
        if (!$s{$count}) { print "Strange error! Unable to create socket $count!\n"; } else { $writeset->add($s{$count}; print "Opened socket $count\n"; }
    }
    while ( ! ( defined ( $s{$count} ) ) )
    
    do
    {
        my $tmp = matrixSslNewSession($ssl{$count}, $keys, $sessionid{$count}, 0)
        if ($tmp) { print "Strange error! Unable to create MatrixSSLNewSession! $count\n"; } else { print "Done MatrixSSLNewSession $count\n"; }
    }
    while ( ! $tmp)    

    do
    {
        my $tmp = matrixSslEncodeClientHello($ssl{$count}, $keys, $sslout{$count}, 0)
        if ($tmp) { print "Strange error! Unable to create MatrixSSLEncodeClientHello! $count\n"; } else { print "Done MatrixSSLEncodeClientHello $count\n"; }
    }
    while ( ! $tmp)
    
    $socketstate{$count} = "I";
    $httpstate{$count} = "U";
    $sslstate{$count} = "C";
	$handshakestate{$count} = "N";
    $times{$count} = time+30;
}



# Initialize SSL contexts

do
{
    my $tmp = matrixSslOpen();
    if ($tmp) { print "Strange error! Unable to open MatrixSSL!\n"; } else { print "Opened MatrixSSL\n"; }
}
while ( ! $tmp)

do
{
    my $tmp = matrixSslReadKeys($keys, undef, undef, undef,undef)
    if ($tmp) { print "Strange error! Unable to MatrixSSLReadKeys!\n"; } else { print "Done MatrixSSLReadKeys\n"; }
}
while ( ! $tmp)


for ($count =1;$count <= $loop;$count++)
{
    &create_socket_irctc($count);
}

sub check_timer
{
	my $count = $_[0];
	if ($times{$count} <= time)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}
#All done. Now the hardwork of timing.

#Login socket
#Send login data and get session id and engine id.
#If failed create socket again add to write pool and retry.
#If read not complete add to read pool and wait.
#If 3 mins are over and operation not complete then close socket and retry.

#Start main loop
&loop;


#Generic Read Write Update loop
#Process socket state within loop
#Process sslstate and httpstate outside

sub loop
{

    my $wait = sort {$a cmp $b} values %times;
    
    if (($readable,$writeable) = IO::Select->select($readset, $writeset, undef, $wait))
    {
        #Send client hello on each socket.
        #Errors and close can be handled only on sysread and syswrite

        foreach (@$writeable)
        {
            my %reverse = reverse %s;
            my $count = $reverse{$_};
			my $n = syswrite ( $_, $sslout{$count});
            if (!defined $n && !$!{EWOULDBLOCK})
            {
                #Error occured on socket. Call irctc socket again.
                print "Error occurred on socket $count\n";
                close($_);
                $writeset->remove($_);
                $readset->remove($_);
                #Need to decide what socket to create as replacement. Need not always be irctc. Can be payment gateway also.
                &create_socket_irctc($count);
				#Process next socket
                next;
            }
       
            #Truncate ssl output string
            substr($sslout{$count}, 0, $n, q{});
			$socketstate{$count} = "N";
            &process_ssl_state($count);
			&process_http_state($count);
       
        }
        foreach (@$readable)
        {
            my %reverse = reverse %s;
            my $count = $reverse{$_};
            #All reads should goto sslin since we arent doing any unencyrpted sockets?!
            my $n = sysread ($_, $sslin{$count},102400,length($sslin{$count}));
            #Case error
            if (!defined $n && !$!{EWOULDBLOCK})
            {
                #Error occured on socket. Call irctc socket again.
           
                close($_);
                $readset->remove($_);
                $writeset->remove($_);
                #Need to decide what socket to create as replacement. Need not always be irctc. Can be payment gateway also.
                &create_socket_irctc($count);
                next;
            }
            #Case normal eof
            if ($n == 0)
            {
                close($_);
                $readset->remove($_);
                $writeset->remove($_);
				$socketstate{$count} = "C";
                &process_http_state($count);
                #0 is normal close
                # Rest of cleanup needs to be done. Process operation state should handle it
            }
            #1 is socket is active
			$socketstate{$count} = "N";
            &process_ssl_state($count);
			&process_http_state($count);
           
       
        }
    }
    else
    {
        #Select Timeout occurred. process timeout(s) here
    }
}

sub process_ssl_state
{
    my $count = $_[0];
	if ($sslstate{$count} eq "C")
	{
		#Check if Client hello sent
		if (length($sslout{$count}) == 0)
		{
			#Read some data
			$writeset->remove($s{$count});
			$readset->add($s{$count});
			$sslstate{$count} = "R";
		}
		#Else wait for sending to finish
	}
	elsif ($sslstate{$count} eq "R")
	{
		#Do some ssldecode
		if (length($sslin{$count})
		{ 
			my ($error, $alertLevel, $alertDescription);
			my $rc = matrixSslDecode($ssl{$count}, $sslin{$count}, my $tmp=q{}, $error, $alertLevel, $alertDescription);
			if ($rc == $SSL_PROCESS_DATA)
			{
				print "Got decoded app data on $count\n";
				$in{$count} .= $tmp;
				#Impossible that handshake was completed in one send and receive but anyway
				if (matrixSslHandshakeIsComplete($ssl{$count})
				{
					$handshakestate{$count} = "Y";
					print "Handshake done on $count\n";
				}
				$sslstate{$count} = "N"; #Normal
				$readset->remove($s{$count});
				$writeset->remove($s{$count}); #Let httpstate do further processing
			}
			elsif ($rc == $SSL_SEND_RESPONSE)
			{
				print "Got ssl protocol data to be sent on $count\n";
				$sslout{$count} .= $tmp;
				$writeset->add($s{$count});
				$readset->add($s{$count});
				$sslstate{$count} = "W"; #Data to be written
			}
			elsif ($rc == $SSL_PARTIAL)
			{
				print "Need more data to decode $count\n";
				$readset->add($s{$count});
				$sslstate{$count} = "R"; #Data to be read
			}
			elsif ($rc == $SSL_SUCCESS)
			{
				print "Handshake done on $count\n";
				$readset->remove($s{$count});
				$writeset->remove($s{$count});
				$sslstate{$count} = "N"; #HTTP state should do further processing
				if (matrixSslHandshakeIsComplete($ssl{$count})
				{
					$handshakestate{$count} = "Y";
					print "Handshake done on $count\n";
				}
			}
			else
			{
				#Error condition
				close ($s{$count});
				$readset->remove($s{$count});
				$writeset->remove($s{$count});
				&create_socket_irctc($count);
			}
		}
	}
}

sub process_http_state
{
		my $count = $_[0];
		if ($socketstate{$count} eq "N")
		{
			if ($socketstate{$count} eq "N")
			{
				#Cleared two levels of normalcy
				if ($httpstate{$count} eq "U")
				{
					if ($count == 1)
					{
						&process_login;
					}
					elsif ($count == 2)
					{
						&process_planner_ajax_action;
					}
					elsif ($count == 3)
					{
						&process_book_ticket_1;# Send train details
					}
					elsif ($count == 4)
					{
						&process_book_ticket_2;# Send passenger details
					}	
					elsif ($count == 5)
					{
						&process_book_ticket_3;# Click make payment button
					}
					elsif ($count == 6)
					{
						&process_book_ticket_4;# Choose payment gateway
					}
					elsif ($count == 7)
					{
						&maintain_login;# Maintain login
					}
					elsif ($count == 8)
					{
						&get_captcha;# process captcha
					}
					