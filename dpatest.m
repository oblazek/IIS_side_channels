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


% Build a matrix of hypothetical intermediate values inside the cipher for all possible keys and traces
% create power hypothesis for each byte of the key
% correlate that with the power traces to extract key
amountoftraces = 100; % up to 10000

% do for every byte
for byte = 1:16
    
    % 256 possible bytes
    powerHyphotesis = zeros(amountoftraces,256);
    for keycandidate = 0:255                            
        % create power hyphothesis
        
    end;
    % function mycorr returns the correlation coeficients matrix calculated
    % from the power consumption hypothesis matrix powerHypothesis and the
    % measured power traces. The resulting correlation coeficients stored in
    % the matrix CC are later used to extract the correct key.
    
    % Calculate correlation coefficients matrix by using power consumption hypothesis matrix 
    % powerhyphotesis and traces. Save to new matrix and use it to extract correct key
    

end;
