## Scrapy
This command will download and install Scrapy along with its dependencies, preparing your environment for building our spider.

### ReconSpider

```shell-session
$ python3 ReconSpider.py http://inlanefreight.com
```

### results.json

After running `ReconSpider.py`, the data will be saved in a JSON file, `results.json`.

```json
{
    "emails": [
        "lily.floid@inlanefreight.com",
        "cvs@inlanefreight.com",
        ...
    ],
    "links": [
        "https://www.themeansar.com",
        "https://www.inlanefreight.com/index.php/offices/",
        ...
    ],
    "external_files": [
        "https://www.inlanefreight.com/wp-content/uploads/2020/09/goals.pdf",
        ...
    ],
    "js_files": [
        "https://www.inlanefreight.com/wp-includes/js/jquery/jquery-migrate.min.js?ver=3.3.2",
        ...
    ],
    "form_fields": [],
    "images": [
        "https://www.inlanefreight.com/wp-content/uploads/2021/03/AboutUs_01-1024x810.png",
        ...
    ],
    "videos": [],
    "audio": [],
    "comments": [
        "<!-- #masthead -->",
        ...
    ]
}
```

| JSON Key         | Description                                                            |
| ---------------- | ---------------------------------------------------------------------- |
| `emails`         | Lists email addresses found on the domain.                             |
| `links`          | Lists URLs of links found within the domain.                           |
| `external_files` | Lists URLs of external files such as PDFs.                             |
| `js_files`       | Lists URLs of JavaScript files used by the website.                    |
| `form_fields`    | Lists form fields found on the domain (empty in this example).         |
| `images`         | Lists URLs of images found on the domain.                              |
| `videos`         | Lists URLs of videos found on the domain (empty in this example).      |
| `audio`          | Lists URLs of audio files found on the domain (empty in this example). |
| `comments`       | Lists HTML comments found in the source code.                          |

### Question

1. After spidering inlanefreight.com, identify the location where future reports will be stored. Respond with the full domain, e.g., files.inlanefreight.com.
```shell
> python3 ReconSpider.py http://inlanefreight.com
> cat result.json | grep report
"<!-- TO-DO: change the location of future reports to inlanefreight-comp133.s3.amazonaws.htb -->",

Answer: inlanefreight-comp133.s3.amazonaws.htb
```