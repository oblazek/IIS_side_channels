% googling gave some hints:
% https://rozvoj.fit.cvut.cz/Lisbon/Analysis
% http://www.dpacontest.org/v2/data/attack_win.m

clc
pwd
clear
% load plaintext, ciphertext and traces for 
load obtained_files_for_attacks/dpa_files/challenge.mat;

% plot(traces(1,:));
trace1 = traces(10, :);
trace2 = traces(20, :);

% average (mean) value for trace
average1 = mean(trace1);
average2 = mean(trace2);

% TODO: CORRELATE POWER TRACES

% align traces to match
% trace2 = trace2*(average1/average2);
% average3 = mean(trace2);

% test - plot two traces
offset = 350;
L = 1200;
plot(offset:L, trace1(offset:L), 'r', (offset:L), trace2(offset:L), 'b');
% one operations length about 80
% amplitude goes roughly between +20 - -20


% First we should approximate the power consumtion of the SubBytes Operation, via the Hamming_Weight Power Model and 
% guessed Key-values

% TODO: SubBytes here - I guess we can  use the one from simple fault, but just the operation
function [SbOutput] = SubBytes(state, lengthOfBytes)
    %sbox() ----- max.: sbox(16, 63:64)
    %      0 3:4;  1 7:8   2 11:12 3      4       5        6       7
    sbox = [
        '0x63', '0x7C', '0x77', '0x7B', '0xF2', '0x6B', '0x6F', '0xC5', '0x30', '0x01', '0x67', '0x2B', '0xFE', '0xD7', '0xAB', '0x76';
        '0xCA', '0x82', '0xC9', '0x7D', '0xFA', '0x59', '0x47', '0xF0', '0xAD', '0xD4', '0xA2', '0xAF', '0x9C', '0xA4', '0x72', '0xC0';
        '0xB7', '0xFD', '0x93', '0x26', '0x36', '0x3F', '0xF7', '0xCC', '0x34', '0xA5', '0xE5', '0xF1', '0x71', '0xD8', '0x31', '0x15';
        '0x04', '0xC7', '0x23', '0xC3', '0x18', '0x96', '0x05', '0x9A', '0x07', '0x12', '0x80', '0xE2', '0xEB', '0x27', '0xB2', '0x75';
        '0x09', '0x83', '0x2C', '0x1A', '0x1B', '0x6E', '0x5A', '0xA0', '0x52', '0x3B', '0xD6', '0xB3', '0x29', '0xE3', '0x2F', '0x84';
        '0x53', '0xD1', '0x00', '0xED', '0x20', '0xFC', '0xB1', '0x5B', '0x6A', '0xCB', '0xBE', '0x39', '0x4A', '0x4C', '0x58', '0xCF';
        '0xD0', '0xEF', '0xAA', '0xFB', '0x43', '0x4D', '0x33', '0x85', '0x45', '0xF9', '0x02', '0x7F', '0x50', '0x3C', '0x9F', '0xA8';
        '0x51', '0xA3', '0x40', '0x8F', '0x92', '0x9D', '0x38', '0xF5', '0xBC', '0xB6', '0xDA', '0x21', '0x10', '0xFF', '0xF3', '0xD2';
        '0xCD', '0x0C', '0x13', '0xEC', '0x5F', '0x97', '0x44', '0x17', '0xC4', '0xA7', '0x7E', '0x3D', '0x64', '0x5D', '0x19', '0x73';
        '0x60', '0x81', '0x4F', '0xDC', '0x22', '0x2A', '0x90', '0x88', '0x46', '0xEE', '0xB8', '0x14', '0xDE', '0x5E', '0x0B', '0xDB';
        '0xE0', '0x32', '0x3A', '0x0A', '0x49', '0x06', '0x24', '0x5C', '0xC2', '0xD3', '0xAC', '0x62', '0x91', '0x95', '0xE4', '0x79';
        '0xE7', '0xC8', '0x37', '0x6D', '0x8D', '0xD5', '0x4E', '0xA9', '0x6C', '0x56', '0xF4', '0xEA', '0x65', '0x7A', '0xAE', '0x08';
        '0xBA', '0x78', '0x25', '0x2E', '0x1C', '0xA6', '0xB4', '0xC6', '0xE8', '0xDD', '0x74', '0x1F', '0x4B', '0xBD', '0x8B', '0x8A';
        '0x70', '0x3E', '0xB5', '0x66', '0x48', '0x03', '0xF6', '0x0E', '0x61', '0x35', '0x57', '0xB9', '0x86', '0xC1', '0x1D', '0x9E';
        '0xE1', '0xF8', '0x98', '0x11', '0x69', '0xD9', '0x8E', '0x94', '0x9B', '0x1E', '0x87', '0xE9', '0xCE', '0x55', '0x28', '0xDF';
        '0x8C', '0xA1', '0x89', '0x0D', '0xBF', '0xE6', '0x42', '0x68', '0x41', '0x99', '0x2D', '0x0F', '0xB0', '0x54', '0xBB', '0x16'
    ];

    for i = 1 : lengthOfBytes

        a = state(1, i); %we are taking only the first 16B from the aes blocks.. there are 9 more..  
        %disp('a: '), a
        a = dec2hex(a);

        if (length(a) == 1)
            if (a == 'A' || a == 'B' || a == 'C' || a == 'D' || a == 'E' || a == 'F' || a == '0' || a == '1' || a == '2' || a == '3' || a == '4'|| a == '5' || a == '6'|| a == '7' || a == '8' || a == '9')               
                if a == '0'
                    tmp1 = '0';
                    tmp2 = '0';
                else       
                    tmp1 = a(1); 
                    tmp2 = '0';
                end
            end
        else
            tmp1 = a(1);
            tmp2 = a(2);
        end %end of if (a == 'A' .....)
    
        tmp1 = hex2dec(tmp1);
        tmp2 = hex2dec(tmp2);

        for b = 0 : 15
            index = 3;
            for c = 0 : 15
                if (b == tmp1 && c == tmp2)
                    helperArray(i, 1:2) = sbox(b+1, index:(index+1));   %
                    SbOutput(i) = hex2dec(helperArray(i, 1:2));         % 
                                                                        %
                end                                                     
                index += 4;   
            end
        end %end of for b = 0 : 15
    end %end of for i = 1 : 16
end %end of SB function

% TODO: POWER MODEL
% Assume high power consumption if the Hamming
% Weight of the output of the first Subbox is high and vice versa
% -> output of first subbox = output of first SubBytes
% ---> "The Hamming weight of a string is the number of symbols 
% ---> that are different from the zero-symbol of the alphabet used."

% Key is right if the predicted power consumption is
% retrievable from the provided power traces

% test - to be the subbox answer
testnumber = 10;
answer = aes_ct(1:testnumber,:);

% amount of values that differ from zero
hammingWeight = sum(answer(:)!=0)


% then we have to correlate the approximated power Traces with the given power Traces to vertify our
% guesst Key-values. 


% Finally we should calculate all 16 Bytes of the Key. 





% http://kutylowski.im.pwr.wroc.pl/articles/hamming.pdf
%It is required for the attack to determine the total Hamming weights of
%the output of the Feistel function of DES during the last round in a series of
%encryptions. This weight consists of weight of the output of an S-Box S we
%2
%are attacking and the output of the remaining S-boxes. For finding the key one
%guesses the subkey bits which go into the XOR gate immediately before S. Then
%it is possible to compute the (hypothetical) outputs of S for the ciphertexts
%at hand. If the subkey bits were guessed correctly, then there is a statistical
%correlation between the weights of the computed outputs of S and the Hamming
%weights measured. For a wrong guess, there is no such a correlation. This is
%a way to determine which guess is correct and thereby to derive the key bits.%
