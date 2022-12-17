clear variables;

% Settings
startFolder = "C:\repos\Data\hesai_128\2022-06-01-16-14-40_Hesai-Lidar-Data.pcap";
title = "Select the Recording";
pointAttributeNr = 3;

% Select Recording
file = uigetfile('*.pcap', title, startFolder);

test = pcap2matlab('', '',file);