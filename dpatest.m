clc
pwd
clear
% load plaintext, ciphertext and traces for 
load obtained_files_for_attacks/dpa_files/challenge.mat;

% plot(traces(1,:));
trace1 = traces(1, :);
trace2 = traces(2, :);

average1 = mean(trace1);
average2 = mean(trace2);

% trace2 = trace2*(average1/average2);
% average3 = mean(trace2);


% plot two traces
L = 1000;
plot(1:L, trace1(1:L), 'r', (1:L), trace2(1:L), 'b');