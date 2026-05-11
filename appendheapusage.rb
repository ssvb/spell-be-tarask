#!/usr/bin/env ruby

md = File.open(ARGV[0])
mu = File.open(ARGV[1])
puts md.gets.strip + " Heap usage |"
puts md.gets.strip + "---:|"
while (l = md.gets)
  abort "incomplete heap usage result\n" unless mu.gets =~ /^Peak heap usage: (\S+)/
  puts l.strip + " #{$1} |"
end
