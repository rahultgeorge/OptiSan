# A number of utility functions for asap-clang

# This file is part of ASAP.
# Please see LICENSE.txt for copyright and licensing information.

require 'shellwords'
require 'open3'
require 'pathname'


SCRIPT_DIR = File.dirname($0)
BAGGY_PASS_DIR="/home/ubuntu/Desktop/SmartMonitor/BaggyBounds"
BAGGY_RT_DIR='/home/ubuntu/Desktop/SmartMonitor/BaggyBounds'
PLACEMENT_PASS_DIR="/home/ubuntu/Desktop/SmartMonitor/Instrumentation"
DENY_LIST_DIR="home/ubuntu/Desktop/SmartMonitor/denyLists"
LOG_FILE_NAME ="pdq_log.txt"

# Running external commands
# =========================

class RunExternalCommandError < StandardError
end

def run!(*args)
  # puts "Running: ",args
  kwargs = if args.last.is_a?(Hash) then args.pop else {} end
  $stderr.puts Shellwords.join(args) if $VERBOSE
  if not system(*args, kwargs)
    raise RunExternalCommandError, "Command #{args[0]} failed with status #{$?}"
  end
end

def runWithOutput!(*args)
  kwargs = if args.last.is_a?(Hash) then args.pop else {} end
  $stderr.puts Shellwords.join(args) if $VERBOSE
  stdout,status = Open3.capture2(*args)
  if not status
    raise RunExternalCommandError, "Command #{args[0]} failed with status #{$?}"
  end
  return stdout.split("\n")
end

# Finding stuff in the path
# =========================

# Cross-platform way of finding an executable in the $PATH.
# From https://stackoverflow.com/questions/2108727/which-in-ruby-checking-if-program-exists-in-path-from-ruby
#
#   which('ruby') #=> /usr/bin/ruby
#
def which(cmd)
  exts = ENV['PATHEXT'] ? ENV['PATHEXT'].split(';') : ['']
  ENV['PATH'].split(File::PATH_SEPARATOR).each do |path|
    exts.each { |ext|
      exe = File.join(path, "#{cmd}#{ext}")
      return exe if File.executable? exe
    }
  end
  return nil
end

def find_clang()
  clang = $0.sub(/my-clang(\+\+)?$/, 'clang\\1')
  #wllvm = $0.sub(/my-clang(\+\+)?$/, 'wllvm\\1')
  raise "cannot find clang" if $0 == clang
  clang
end

def find_opt()
  opt = $0.sub(/my-clang(\+\+)?$/, 'opt')
  raise "cannot find opt" if $0 == opt
  opt
end

def find_llc()
  llc = $0.sub(/my-clang(\+\+)?$/, 'llc')
  raise "cannot find llc" if $0 == llc
  llc
end

def find_llvm_link()
  llvm_link = $0.sub(/my-clang(\+\+)?$/, 'llvm-link')
  raise "cannot find llvm-link" if $0 == llvm_link
  llvm_link
end

def find_ar()
  which('ar')
end

def find_asap_lib()
  #soPath=File.expand_path('../lib/libSanityChecks.so', SCRIPT_DIR)
  #puts "#{SCRIPT_DIR} #{soPath}"
  ["#{SCRIPT_DIR}/../lib/libSanityChecks.dylib",
   "#{SCRIPT_DIR}/../lib/libSanityChecks.so"].find { |f| File.file?(f) }

end

def find_extract_bc()
  puts $0
  extract_bc = $0.sub(/my-clang(\+\+)?$/, 'extract-bc')
  raise "cannot find extract-bc" if $0 == extract_bc
  extract_bc
end


def find_baggy_pass_lib()
  ["#{BAGGY_PASS_DIR}/libBaggyBounds.dylib",
   "#{BAGGY_PASS_DIR}/libBaggyBounds.so"].find { |f| File.file?(f) }
end

def find_baggy_lib()
  #puts "#{BAGGY_RT_DIR}/baggylib.a"
  ["#{BAGGY_RT_DIR}/libbaggy_rt_lib.a",
   "#{BAGGY_RT_DIR}/baggy_rt_lib.a"].find { |f| File.file?(f) }
end

def find_sanitization_helper_pass()
  ["#{PLACEMENT_PASS_DIR}/libSanitizerHelperPass.so",
    "#{PLACEMENT_PASS_DIR}/libSanitizerHelperPass.dylib"
  ].find { |f| File.file?(f) }
end  

def find_tce_pass()
  ["#{PLACEMENT_PASS_DIR}/libTurnOffChecks.so",
    "#{PLACEMENT_PASS_DIR}/libTurnOffChecks.dylib"
  ].find { |f| File.file?(f) }
end  


# Transforming file names
# =======================

def mangle(name, ext, new_ext)
  raise "name does not end in #{ext}: #{name}" unless name.end_with?(ext)
  name.sub(/#{Regexp.escape(ext)}$/, new_ext)
end


# Dealing with compiler arguments
# ===============================

# Retrieves the argument that matches a given pattern. This function tries to
# be slightly smart, knowing special cases for common patterns.
# The 'multiple' parameter can be set to :first, :last or to some index. If
# set, multiple values for the option are allowed, and the corresponding one
# will be returned.
def get_arg(args, pattern, multiple=nil)
  if ['-o', '-MF'].include? pattern
    i = args.index(pattern)
    return i ? args[i + 1] : nil
  end

  if pattern.is_a?(Regexp)
    result = args.find_all { |a| a =~ pattern }
  elsif pattern.end_with?('=')
    regexp = /#{Regexp.escape(pattern)}(.*)/
    result = args.collect { |a| if a =~ regexp then $1 else nil end }.compact
  else
    result = args.find_all { |a| a == pattern }
  end

  raise "more than one argument matching #{pattern}" if result.size > 1 and not multiple
  return result[0] if multiple == :first
  return result[-1] if multiple == :last
  return result[multiple || 0]
end

def remove_arg(args, pattern)
  if pattern.is_a?(Regexp)
    args.reject { |a| a =~ pattern }
  else
    args.reject { |a| a == pattern }
  end
end

# Ensures arg is contained in args. Does not introduce duplicates.
def insert_arg(args, arg)
  if arg =~ /^-g/
    args = remove_arg(args, '-g0')
    return args if args.find { |a| a == '-g' }
  end

  return args if args.find { |a| a == arg }
  [arg] + args
end

def insert_linker_arg(args,arg)
  if arg =~ /^-g/
    args = remove_arg(args, '-g0')
    return args if args.find { |a| a == '-g' }
  end

  return args if args.find { |a| a == arg }
  args + [arg]
end  


# Gets the optimization level, but sanitize it to one of the values that LLC understands
def get_optlevel_for_llc(args)
  # Don't use /^-O.$/ here, because llc only knows numeric levels
  get_arg(args, /^-O[0123]$/, :last) || '-O3'
end


# PDQ - logging
def log(message)
    #puts "Logging: #{message}"
    File.open(LOG_FILE_NAME, "a+") do |logFile|
        logFile.syswrite(message+"\n")
    end
    return true
end

def get_containing_path(path_name)
  curr_path_name=Pathname.new(path_name)
  return curr_path_name.dirname
end



