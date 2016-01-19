% googling gave some hints:
% https://rozvoj.fit.cvut.cz/Lisbon/Analysis
% http://www.dpacontest.org/v2/data/attack_win.m

clc
pwd
clear
% load plaintext, ciphertext and traces for 
load obtained_files_for_attacks/dpa_files/challenge.mat;

% plot(traces(1,:));
trace1 = traces(1, :);
trace2 = traces(2, :);

% average (mean) value for trace
average1 = mean(trace1);
average2 = mean(trace2);

% align traces to match
% trace2 = trace2*(average1/average2);
% average3 = mean(trace2);


% plot two traces
L = 1000;
plot(1:L, trace1(1:L), 'r', (1:L), trace2(1:L), 'b');


% POWER MODEL
% Assume high power consumption if the Hamming
% Weight of the output of the first Subbox is high and vice versa
% -> output of first subbox = output of first SubBytes
% ---> "The Hamming weight of a string is the number of symbols 
% ---> that are different from the zero-symbol of the alphabet used."

% Key is right if the predicted power consumption is
% retrievable from the provided power traces



% AddRoundKey here

% SubBytes here

% to be the subbox answer
testnumber = 10;
answer = aes_ct(1:testnumber,:);
hammingWeight = sum(answer(:)!=0)




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
