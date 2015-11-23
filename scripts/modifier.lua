function packet_seen(inbound, frame)
    if math.random() < 0.05 then
        set_byte(frame, math.random(40, get_len(frame)), math.random(255))
    end
    send_packet(not inbound, frame)
end

