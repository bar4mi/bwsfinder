#!/usr/bin/perl -w
# =======================================================================
# =  Bar4mi WebShell Finder Ver. 0.5 (Simon Ryeo, bar4mi@gmail.com)     =
# =======================================================================
#
# The main purpose of this program is to find a webshell uploaded by 
# a hacker or malicious internal user. 
#
# License: GPLv3
# Current Supported Language: PHP, ASP, JSP
# HomePage: http://bar4mi.tistory.com
# Start Date: 02/12/2010
# Last Modified Date: 07/01/2010
# =======================================================================
# To Do. 
#  1. improve it's execution speed (not matching a line)
#  2. provide a option for size (OK!)
#  3. provide a options for excluding file extentions (OK!)
#  4. print results ASAP (OK!)
#  5. print execution time (OK!)
#  6. check only text file (OK!)
#  7. reformat printed time for fingerprint (OK!)
#  8. print current progress without any additional module (OK!)
# =======================================================================
 
# ==================
# = Define modules =
# ==================
use strict;
use warnings;
use Getopt::Std;
use File::Find;
use IO::File;
use Digest::MD5;
use File::stat;
# use Time::localtime;
use IO::Handle;
# eval {
# 	require Term::ProgressBar;
# 	Term::ProgressBar->import();
# };
# if ($@) {
# 	# print "Need to install Term::ProgressBar\r\n";
# 	# 	exit();
# 	
# }

# ====================
# = Define constants =
# ====================
use constant TRUE => 1;
use constant FALSE => 0;
use constant DEBUG => 1;
use constant EXPEXT => "\\/|\\.(jpg|gif|png|ico|xml|swf|css|doc|pdf|ppt|xls|zip|tar|tz|gz|rar|exe)\$";
use constant PHPEXT => "\\.(php|php4|html|htm|phps|inc|ph|pthml|php5|php3)*\$";
use constant ASPEXT => "\\.(asp|apsx|cer|asa|html|htm)*\$";
use constant JSPEXT => "\\.(jsp)*\$";
use constant MAXSIZE => 100;

# ===========================
# = Define global variables =
# ===========================
my $s_ver = "0.5";
my %option = ();
my ($s_webdir, $s_type, $s_ext, $s_mode, $s_size, @s_exclude);		# option variables
my (@s_files, $s_file);					# valid files to match
my (%s_pattern, %m_pattern);			# match pattern
my (@s_result, @m_result, $result, @f_result);		# results
my ($m_time, $c_time);								# time variable
my $f_cnt = 0;
my $t_file = 0;
my $output;											# store results 
my $r_file;											# filename to store result
my $e_time;								# Execution time
my $progress;							# progress
my $p_cnt = 0;							# progress count

# ====================
# = Define Functions =
# ====================
# Print program header
sub print_header {
	print "#"x80 . "\r\n";
	print "#" . " "x78 . "#\r\n";
	print "#       Bar4mi WebShell Finder Ver." . $s_ver . " (Simon Ryeo, bar4mi\@gmail.com)          #\r\n";
	print "#" . " "x78 . "#\r\n";
	print "#"x80 . "\r\n";
}

# print program arguments
sub print_input {
	print ">>> Directory: " . $s_webdir . "\r\n";
	print ">>> Mode: ";
	
	if ($s_mode eq "w") {
		print "Find Webshells\r\n";
	} elsif ($s_mode eq "l") {
		print "Print file list to check\r\n"
	} else {
		print "Check fingerprint\r\n"
	}
	
	print ">>> Max File Size: <= " . $s_size / 1024 . " Bytes\r\n";
	
}

# Print help infomation
sub print_help {
	print_header();
	print "Usage: $0 [options] -m [mode] -t [type] -d [Webroot Directory]\r\n";
	print "[Option]\r\n";
	print "\t-d [Webroot]: *ESSENTIAL* the path that web files exist\r\n";
	print "\t-t [type]: *ESSENTIAL* a type of language\r\n";
	print "\t-m [w/l/f] *ESSENTIAL*\r\n";
	print "\t\tw: only check webshells\r\n";
	print "\t\tl: only print file list to check\r\n";
	print "\t\tf: only print a fingerprint\r\n";
	print "\t-r [filename]: save a result to file\r\n";
	print "\t-e: enable this to search only defined extension files\r\n";
	print "\t-s [max size(KB)]: limit max file size(default 100KB)\r\n";
	print "\t-x [Directory]: Directory lists to exclude(separated by comma)\r\n";
	print "\r\n";
}

# Print progress
sub print_progress {
	my $t_cnt = $_[0];		# Total Count
	my $t_num = $_[1];		# Previous Number
	my $c_cnt = $_[2];		# Current Count
	# my $c_num = $_[3];		# Previous Number
	my $c_stat; 			# Current Progress Status
	
	$c_stat = int(($c_cnt/$t_cnt) * 100);
	# print "\r\n\$t_cnt " . $t_cnt . " : \$t_num " . $t_num . " : \$c_cnt " . $c_cnt . " : \$c_stat " . $c_stat . "\r\n";
	
	# Print Start
	if ($c_cnt == 0) {
		print "[";
	}
	# elsif ($c_stat % 5 == 0) {
	elsif ($c_stat >= (($t_num + 1) * 5)) {
		print "#";
		$t_num++;
	}
	
	# Print End
	if ($t_cnt == ($c_cnt+1)) {
		print "#]\r\n";
	}
	
	return $t_num;
}


# Get options
sub get_options {
	getopts("d:t:r:em:s:x:", \%option);

	if (defined($option{d}) && defined($option{t}) && defined($option{m})) {
		$s_webdir = $option{d};

		# Check a type of program language
		# Currently it only supports PHP.
		if ($option{t} =~ /(php|asp|jsp)/) {
			$s_type = $option{t};
		}
		else {
			return FALSE;
		}

		# Check a file name
		if ($option{r})  {
			$r_file = $option{r};
		}

		# Get whether to find all valid files or related files
		$s_ext = $option{e}; 
		
		# Get directory list to exclude
		if (defined($option{x})) {
			@s_exclude = split(',', $option{x});
		}

		# Get the mode value
		if ($option{m} ne "") {
			$s_mode = $option{m};
		} 
		else {
			return FALSE;
		}
		
		# Get max file size
		if (defined($option{s})) {
			if ($option{s} =~ /^\d+$/) {
				$s_size = $option{s} * 1024;
			} 
			else {
				return FALSE;
			}
		}
		else {
			# default max size is 1MB.
			$s_size = MAXSIZE * 1024;
		}		
		
		return TRUE;
	}
	else {
		return FALSE;
	}

}

# Return whether a file analyzes
sub check_file {
	my $f_fname = $File::Find::name;
	my $extpat;
	my $check;
	
	# Except files in the except list
	if(defined($option{x})) {
		$check = TRUE;
		foreach my $x (@s_exclude) {
			if($f_fname =~ /$x/) {
				$check = FALSE;
			} 
		}
		
		if(!$check) {
			return;
		}
	}
	
	# print if it is directory
	if (-d $f_fname) {
		print "\rReading from " . $f_fname;
		# sleep(1);
		foreach (1 .. length($f_fname)) {
		  print "\b";
		  # sleep(2);
		}		
	}
	
	
	# Only files && Eliminate unnessary files (Just only check a text file)
	if (!$s_ext && $s_mode ne "f") {
		if (-f $f_fname && -T $f_fname && $f_fname !~ /EXPEXT/i) {
			push @s_files, $f_fname;
		}
	}
	else {
		# Get valid extensions
		if ($s_type =~ /php/i) {
			$extpat = PHPEXT;
		} 
		elsif ($s_type =~ /asp/i) {
			$extpat = ASPEXT;
		}
		elsif ($s_type =~ /jsp/i) {
			$extpat = JSPEXT;
		}

		# Get valid files related with current type
		if (-f $f_fname && -T $f_fname && $f_fname =~ /$extpat/i) {
			push @s_files, $f_fname;
		}
	}
# 	my $f_length = length($f_fname);
# 	print $f_fname;
# 	sleep 1;
# 	print " \b" x $f_length;
}

# Get files in the web root directory
sub get_files {
	my $g_dir = $_[0];

	if (-d $g_dir) {
		find(\&check_file, $g_dir);
		print "\r\n";
	}
	else {
		print STDERR "Can't open $g_dir!\r\n";
		exit();
	}
}

# Return a search result 
sub search_suspicious_func {
	my ($r_key, $r_value);
	my $p_num = 0;
	my $p_flag = FALSE;					# needed by line pattern matching
	my $fname = $_[0];
	# my $f_content;							# the content read from a file

	# local $/=undef;
	
	open(FH, "< $fname")
		or print STDERR "Unable to open " . $fname . "!";

	# $f_content = <FH>;
	# 
	# # Verify known patternslocal
	# while (($r_key, $r_value) = each(%m_pattern)) {
	# 	# print "r_key: $r_key\r\n";
	# 	if ($f_content =~ m/\Q$r_value\E/ix) {
	# 		push @m_result, [$r_key, $fname];
	# 		last;
	# 	}
	# }
	# 
	# # Verify suspicious function patterns
	# if ($s_mode ne "w" && $p_flag eq FALSE && keys %s_pattern) {
	# 	while (($r_key, $r_value) = each(%s_pattern)) {
	# 		if ($f_content =~ m/\Q$r_value\E/ix) {
	# 			push @s_result, [$r_key, $fname];
	# 			last;
	# 		}
	# 	}		
	# }

	# This method matchs the string by a line
	while(<FH>){
		$p_num++;
		# Verify known pattern
		while (($r_key, $r_value) = each(%m_pattern)) {
			if ($_ =~ m/\Q$r_value\E/ix) {
				$p_flag = TRUE;
				push @m_result, [$r_key, $fname, $p_num, $_];
				# print $fname . ": " . $_;
				last;
			}
		}
	
		# Verify suspicious func
		if (!$s_mode ne "w" && $p_flag ne TRUE && keys %s_pattern) {
			while (($r_key, $r_value) = each(%s_pattern)) {
				if ($_ =~ m/\Q$r_value\E/ix) {
					$p_flag = TRUE;
					push @s_result, [$r_key, $fname, $p_num, $_];
					# print $fname . ": " . $_;
					last;
				}
			}
		}
	
		if ($p_flag eq TRUE) {
			last;
		}
	
	}
	
	close(FH);
}

# Read suspicious_pattern
sub get_suspicious_func
{
	my @temp;

	open(REGP, "< $_[0]") 
		or die("Unable to open $s_type pattern file");

	while(<REGP>){
		chomp;
		s/#.*//;
		s/^\s+//;
		s/\s+$//;

		if ($_ ne "") {
			@temp = split(":", $_, 3);

			if ($temp[0] eq 'M') {
				$m_pattern{$temp[1]} = $temp[2];
			}
			elsif ($temp[0] eq 'S') {
				$s_pattern{$temp[1]} = $temp[2];
			}
		}
	}
	close(REGP);
}

# Get a fingerprint
sub get_fingerprint
{
	my $f_name = $_[0];
	my ($f_mtime, $f_ctime, $f_atime); 
	my $f_digest;
	my @tmp;

	open(FP, "< $f_name")
		or die("Unable to open $f_name!");
	
	# get access time
	@tmp = ();
	@tmp = localtime(stat($f_name)->atime);
	$f_atime = sprintf("%4d/%02d/%02d %02d:%02d:%02d", $tmp[5] + 1900, $tmp[4], $tmp[3], $tmp[2], $tmp[1], $tmp[0]); 
	# get last modified time
	@tmp = ();
	@tmp = localtime(stat($f_name)->mtime);
	$f_mtime = sprintf("%4d/%02d/%02d %02d:%02d:%02d", $tmp[5] + 1900, $tmp[4], $tmp[3], $tmp[2], $tmp[1], $tmp[0]);
	# get inode change time
	@tmp = ();
	@tmp = localtime(stat($f_name)->ctime);	# create time
	$f_ctime = sprintf("%4d/%02d/%02d %02d:%02d:%02d", $tmp[5] + 1900, $tmp[4], $tmp[3], $tmp[2], $tmp[1], $tmp[0]);

	binmode(FP);

#$f_digest = Digest::MD5->new->addfile(*FP)->b64digest;
	$f_digest = Digest::MD5->new->addfile(*FP)->hexdigest;

#print "$f_name : $f_mtime : $f_ctime : $f_digest\r\n" if DEBUG;
	push @f_result, [$f_name, $f_ctime, $f_mtime, $f_atime, $f_digest];
	
	close(FP);
}

sub process_result {
	if (@f_result) {
		$output = sprintf("%s\r\n", "-"x80);
		$output .= sprintf(" File Fingerprints => %d files.\r\n", $#f_result);;
		$output .= sprintf("%s\r\n", "-"x80);
		$output .= sprintf("\t* Hash: MD5 value of a file\r\n\t* Ctime: Inode Change Time\r\n\t* Mtime: Modify Time\r\n\t* Atime: Access Time\r\n");
		$output .= sprintf("%s\r\n", "-"x80);
		$output .= sprintf("========== Hash (MD5) ========== | ====== CTime ====== | ====== MTime ====== | ====== ATime ====== | == Full Path File Name ==> \r\n");
		#                   936d78d7fd5bb305edfa6ac54eb1aca2 | 2010/02/28 16:29:01 | 2009/01/14 20:34:26 -> /Volumes/BK/Finded Webshell/sd.asa

		foreach $result (@f_result) {
			$output .= sprintf("%22s | %s | %s | %s | %s\r\n", $result->[4], $result->[1], $result->[2], $result->[3], $result->[0]);
		}
	}

	if (@m_result) {
		$output .= sprintf("%s\r\n", "-"x80);
		$output .= sprintf(" Malicious Files => %d files\r\n", $#m_result + 1);
		$output .= sprintf("%s\r\n", "-"x80);

		foreach $result (@m_result) {
			$output .= sprintf("%22s: %4s line -> %s\r\n\t%s\r\n", $result->[0], $result->[2], $result->[1], $result->[3]);
			# $output .= sprintf("%22s: %s\r\n", $result->[0], $result->[1]);
		}
	}

	if (@s_result) {
		$output .= sprintf("\r\n");
		$output .= sprintf("%s\r\n", "-"x80);
		$output .= sprintf(" Suspicious Files(These files need to investigate directly.) => %d files.\r\n", $#s_result);
		$output .= sprintf("  - system(), exec(), passtrhu(): used to execute system commands\r\n");
		$output .= sprintf("  - base64_decode(): used to bypass the pattern detection\r\n");
		$output .= sprintf("%s\r\n", "-"x80);

		foreach $result (@s_result) {
			$output .= sprintf("%22s: %4s line -> %s\r\n\t%s\r\n", $result->[0], $result->[2], $result->[1], $result->[3]);
			# $output .= sprintf("%22s: %s\r\n", $result->[0], $result->[1]);
		}
	}


	if($output) {
		print $output;

		if($r_file) {
			open(RF, "> $r_file")
				or die("Unable to write result to $r_file!");

			print RF $output;
			print "\r\nResults saved to " . $r_file . ".\r\n";
		}
	} 
	elsif ($s_mode eq "w") {
		print "No result.\r\n\r\n";
	}

}

# =======================
# = Start main function =
# =======================
if ($#ARGV < 0 || get_options() eq FALSE) {
	print_help();
	exit();
}
print_header();

print_input();

# Get detection patterns for each language
print ">>> Reading patterns\r\n";
get_suspicious_func("$s_type.dat");

# Get valid files to detect suspicious pattern
print ">>> Reading file list\r\n";
$|=1;
get_files($s_webdir);

# Print the exclude directories
if(defined($option{x})) {
	print ">>> Exclude Drectory:\r\n";	
	foreach my $x (@s_exclude) {
		print "    " . $x . "\r\n";
	}
}

# Verify the input and permission are correct
print ">>> Checking files\r\n";
if (!@s_files) {
	print "Please verify the directory path or permission!";
	exit();
}

$t_file = $#s_files + 1;

# print "### Directory: " . $s_webdir . "\r\n";
# print "### Total Files in the directory: " . $t_file . "\r\n\r\n";

# $progress = Term::ProgressBar->new($t_file);
$progress = 0;

# Enable Auto flush
# $|=1;

for $s_file (@s_files){
	# Verify file permission
	if (-r $s_file) {
		# Verify file size
		if (-s $s_file <= $s_size) {
			if ($s_mode eq "l") {
				++$f_cnt;
				printf("%4s: %s\r\n", $f_cnt, $s_file);
			}
			elsif ($s_mode eq "f") {
				get_fingerprint($s_file);
			}
			else {
				search_suspicious_func($s_file);
			}
		}
	}
	
	if ($s_mode ne "l") {
		$progress = print_progress($t_file, $progress, $p_cnt);
		$p_cnt++;
		# $progress->update($p_cnt);
	}
	
}

# print & store results
process_result();

if ($s_mode eq "l") {
	print "\r\n-Total related files: " . $f_cnt . "\r\n";
}

# get the execution time
$e_time = time() - $^T;
# print "time: " . time() . "start: " . $^T;
print ">>> Execution Time: " . $e_time . " secs\r\n\r\n";

# end of program
exit();
