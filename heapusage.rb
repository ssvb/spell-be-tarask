#!/usr/bin/env ruby

nuspell = ARGV.include?("-n")
dumbspell = ARGV.include?("-d")
args = ARGV.filter {|x| !(x =~ /^\-/) }

dicname  = args[0]
wordlist = args[1]

cmdline = "hunspell -d #{dicname} -l #{wordlist} 2>/dev/null | grep heaptrack"
cmdline = "./dumbspell -d #{dicname} -l #{wordlist} 2>/dev/null | grep heaptrack" if dumbspell
cmdline = "nuspell -d #{dicname} #{wordlist} 2>/dev/null | grep heaptrack" if nuspell

heap = "?"
rss  = "?"

result = `heaptrack #{cmdline}`
if result =~ /(heaptrack \-\-analyze.*)/
  result2 = `#{$1.strip}`
  if result2 =~ /peak heap memory consumption\: (\S+)/
    heap = $1
  end
  if result2 =~ /peak RSS \(including heaptrack overhead\)\: (\S+)/
    rss = $1
  end
end

puts "Heap: #{heap}, RSS: #{rss}"
