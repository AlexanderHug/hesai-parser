clear variables;

% Settings
lineNr = 128;
maxPointcloudSize = 300000;
startFolder = "C:\repos\Data\hesai_128\recording1.pcap";
title = "Select the Recording";
srcIp = [192 168 20 51];
dstPort = 2368;

% Select Recording
[fileName, path] = uigetfile('*.pcap', title, startFolder, 'MultiSelect', 'off');
file = fullfile(path, fileName);

pcapReaderObj = pcapReader(file);

LoadChannelAngles();
channelAngles = channelAnglesDeg.* 2 * pi /360;

% Parse ethernet packets
endOfFile = false;
cycle = 0;
pointclouds = cell(0, 1);
pointNr = 0;
pointcloud = zeros(maxPointcloudSize, 4);
azimuthOld1 = 0;

lastwarn('', '');
while endOfFile == false
    
    ethernetPacket = read(pcapReaderObj);
    [warnMsg, warnId] = lastwarn();
    
    endOfFile = ~isempty(warnId);
    if (endOfFile)
        break;
    end
    
    % Parse pcap packet
    ethernetPacket.time = ethernetPacket.Timestamp;

    packet = ethernetPacket.Packet.eth;

    ethernetHeader.destAddr = packet.DestinationAddress;
    ethernetHeader.srcAddr = packet.SourceAddress;
    ethernetHeader.ethType = packet.Type;

    % Parse udp header

    data = uint8(packet.Payload);

    ethernetHeader.protocolData = data(1:12);
    ethernetHeader.srcIp = data(13:16);
    ethernetHeader.dstIp = data(17:20);
    currentBytes = data(21:22);
    valueRaw = typecast(currentBytes, 'uint16');
    ethernetHeader.srcPort = swapbytes(valueRaw);
    currentBytes = data(23:24);
    valueRaw = typecast(currentBytes, 'uint16');
    ethernetHeader.dstPort = swapbytes(valueRaw);
    currentBytes = data(25:26);
    valueRaw = typecast(currentBytes, 'uint16');
    ethernetHeader.length = swapbytes(valueRaw);
    currentBytes = data(26:27);
    valueRaw = typecast(currentBytes, 'uint16');
    ethernetHeader.checksum = swapbytes(valueRaw);

    ipMissmatch = false;
    for i = 1:size(srcIp, 2)     
        if (ethernetHeader.srcIp(i) ~= srcIp(i))
            ipMissmatch = true;
        end
    end

    if (ipMissmatch)
        continue;
    end

    if (ethernetHeader.dstPort ~= dstPort)
        continue;
    end

    % Parse udp packet payload

    preHeader.sop = data(29:30);
    preHeader.protocolVersion = data(31:32);
    preHeader.reserved = data(33:34);

    header.laserNr = data(35);
    header.blockNr = data(36);
    header.firstBlockReturn = data(37);
    header.distUnit = data(38);
    header.returnNr = data(39);
    header.flags = data(40);

    currentBytes = data(41:42);
    body.azimuthOffset1 = typecast(currentBytes, 'uint16');
    body.block1 = data(43:426);
    currentBytes = data(427:428);
    body.azimuthOffset2 = typecast(currentBytes, 'uint16');
    body.block2 = data(429:812);
    body.crc1 = data(813:816);

    ethernetPacket.ethernetHeader = ethernetHeader;
    ethernetPacket.preHeader = preHeader;
    ethernetPacket.header = header;
    ethernetPacket.body = body;

    for blockIdx = 1:2
        if (blockIdx == 1)
            block = ethernetPacket.body.block1;
            azimuthOffset = double(ethernetPacket.body.azimuthOffset1) * 2 * pi / (100*360);
        else
            block = ethernetPacket.body.block2;
            azimuthOffset = double(ethernetPacket.body.azimuthOffset2) * 2 * pi / (100*360);
        end
        
        distancesRaw = zeros(lineNr, 1);
        reflectivities = zeros(lineNr, 1);
        for i = 1:lineNr
            currentBytes = block((i - 1)*3 + 1 : (i - 1)*3 + 3);
            distancesRaw(i) = typecast(currentBytes(1:2), 'uint16');
            reflectivities(i) = currentBytes(3);
            
        end
        distUnit = double(header.distUnit);
        distances = distancesRaw.*(distUnit/1000);

        points = zeros(lineNr, 3);
        for i = 1:lineNr
            pointRaw = [distances(i), 0, 0]';
            azimuth = channelAngles(i, 1) + azimuthOffset;
            elevation = channelAngles(i, 2);
            M = eul2rotm([azimuth, elevation, 0]);
            point = M * pointRaw;
            points(i, :) = [point(1:2)', -point(3)]; 
        end
        for i = 1:lineNr
            point = points(i, :);
            pointNr = pointNr + 1;
            pointcloud(pointNr, :) = [pointNr, point];
        end
    end

    if (ethernetPacket.body.azimuthOffset1 < azimuthOld1)
        cycle = cycle + 1;
        pointclouds{cycle, 1} = pointcloud(1:pointNr, :);
        pointNr = 0;
        pointcloud = zeros(maxPointcloudSize, 4);
        pointNr = pointNr + 1;
    end
    
    azimuthOld1 = ethernetPacket.body.azimuthOffset1;
end

recording.cycles = cycle;
recording.pointclouds = pointclouds;

fclose all;