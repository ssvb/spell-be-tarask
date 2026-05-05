#!/usr/bin/env ruby

nuspell = ARGV.include?("-n")
args = ARGV.filter {|x| !(x =~ /^\-/) }

dicname  = args[0]
wordlist = args[1]

cmdline = "hunspell -d #{dicname} -l #{wordlist} 2>/dev/null | grep heaptrack"
cmdline = "nuspell -d #{dicname} #{wordlist} 2>/dev/null | grep heaptrack" if nuspell

result = `heaptrack #{cmdline}`
if result =~ /(heaptrack \-\-analyze.*)/
  result2 = `#{$1.strip}`
  if result2 =~ /peak heap memory consumption\: (\S+)/
    puts "Peak heap usage: #{$1}"
  end
end
