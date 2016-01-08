clc
pwd
clear
 % first load the ciphertexts and plaintext through this file..
load obtained_files_for_attacks/simple_fault/challenge.mat
secret = 'hacker';
users_pwd = input ('Enter ur passwd: ', 's');
% a = floor(rand()*100);
prompt = 'Do you want more? Y/N [Y]: ';
str = input(prompt, 's');
if isempty(str)
	str = 'Y'
end
if (strcmp(secret, users_pwd))
	% grant accesss
	disp('Welcome back commander!..')
else
	% deny access
	disp('Incorrect pwd -> Get out of here..')
end

function aes
	disp('This program doesn''t do anything YET.. but wait for it.')
end