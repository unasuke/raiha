class C
  class << self
    def aaa
    Ractor.make_shareable(@bbb)
      @bbb ||= 'fooo'
    end
  end
end

C.aaa

r = Ractor.new(C) do |cls|
  puts "I see #{cls}"
  puts "I can't see #{cls.aaa}"
end
r.take
