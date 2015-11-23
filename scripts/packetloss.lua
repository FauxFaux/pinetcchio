function packet_seen(inbound, frame)
    if math.random() > 0.05 then
        send_packet(not inbound, frame)
    end
end

