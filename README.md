## WPSploit

> Aggressive regex based code scanner for Wordpress Themes/Plugins

![python](https://img.shields.io/badge/python-2.7-brightgreen.svg) ![license](https://img.shields.io/badge/license-MIT-brightgreen.svg)

This tool is intended for Penetration Testers who audit WordPress themes or plugins or developers who wish to audit their own WordPress code. This script should be used for learning purposes only. By downloading and running this script you take every responsibility for wrong or illegal uses of it.

For more informations about the vulnerabilities tested [click here](https://github.com/ethicalhack3r/wordpress_plugin_security_testing_cheat_sheet).

[![demo](https://asciinema.org/a/SKPJtXGr04egsIOeELUMdPAkb.png)](https://asciinema.org/a/SKPJtXGr04egsIOeELUMdPAkb)

## Getting started

Clone the repository code or download the [archive](https://github.com/b4dnewz/wpsploit/archive/master.zip):

```
$ git clone https://github.com/b4dnewz/wpsploit
```

The it's recommended to add wpsploit.py to your local bin with the following commands:

```
$ cd wpsploit
$ ln -s $PWD/wpsploit.py /usr/local/bin/wpsploit
```

Now you can use the __wpsploit__ command from everywhere, have a try:

```
$ wpsploit --help

Usage: wpsploit.py [-h] [-k] [-s] source

Positional arguments:
  source      Can be slug, url, a path to file or directory

Optional arguments:
  -h, --help  show this help message and exit
  -k, --keep  Enable to keep the downloaded zip archive
  -s, --save  Save the scan results to JSON in current folder

Command examples:
  wpsploit some-plugin
  wpsploit /some-plugin/class-main.php
  wpsploit /plugins/some-plugin/
  wpsploit https://wordpress.org/plugins/some-plugin/
```


## Usage

This tool allow you to scan local and remote code very easily, just pass to the script whatever you want to scan, like the examples below:

### Local file

If you want to test a single file only run the command with the relative or absolute path to the file as argument:

```
$ wpsploit ./my-plugin/main.php
```

This example assume you have a folder called my-plugin with a main.php file inside.

### Local folder

Testing a entire project is really easy, just pass the relative or absolute path of the project as argument to the script:

```
$ wpsploit ./wp-content/plugins/some-plugin
```

It will iterate over all .php files and collect results.

### Remote project

Do you want to check if a third party plugin follow the basic security standards? Just pass the unique slug name to the script and it will download and scan for you all in once:

```
$ wpsploit jetpack
```

---

## Development

If you want to contribute to the development of this project, fork it, open a new branch with your features, try to stick as much as possible with the code style and once you are ready submit a pull request, it will be reviewed and in case it's all good, accepted.

## License

This package is under [MIT](https://github.com/b4dnewz/wpsploit/blob/master/LICENSE) License.
