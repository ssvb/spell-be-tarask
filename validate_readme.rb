#!/usr/bin/env ruby
require 'ruby_llm'

RubyLLM.configure do |config|
  config.gemini_api_key = ENV.fetch('GEMINI_API_KEY', nil)
  config.default_model = 'gemini-flash-lite-latest'
end

response = RubyLLM.chat.ask "
  Define one round of review as follows:
  'Compare the Belarusian and English parts of the readme text in the markdown format,
  treating the Belarusian part as the original. Look for major omissions, addition of
  superficial details, incorrect translation, spelling or grammar errors in the English
  translation. Prepare the list of necessary corrections with detailed explanations.
  Completely ignore subjective styistic changes or minor wording preferences, but
  address all undisputed factual and grammar errors even in the cases when they
  don't hinder understanding.'

  Perform 3 independent rounds of review. Compare the outcomes of these 3 rounds
  as a detailed summary text.

  If no corrections are necessary, say 'SUCCESS' (without quotes) as the very last
  word of the response. If corrections are necessary, say 'FAILURE' (without quotes)
  as the very last word of the response. Do not add any punctuation or any other text
  after this final word.", with: "README.md"

puts response.content

exit 1 unless response.content =~ /SUCCESS\s*$/
