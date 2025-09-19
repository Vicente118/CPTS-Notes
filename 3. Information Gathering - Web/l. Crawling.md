`Crawling`, often called `spidering`, is the `automated process of systematically browsing the World Wide Web`. Similar to how a spider navigates its web, a web crawler follows links from one page to another, collecting information.

## How Web Crawlers Work

The basic operation of a web crawler is straightforward yet powerful. It starts with a seed URL, which is the initial web page to crawl. The crawler fetches this page, parses its content, and extracts all its links. It then adds these links to a queue and crawls them, repeating the process iteratively.

### Breadth-First Crawling
![Flowchart showing a Seed URL leading to Page 1, which branches to Page 2 and Page 3. Page 2 connects to Page 4 and Page 5, while Page 3 connects to Page 6 and Page 7.](https://mermaid.ink/svg/pako:eNo90D0PgjAQBuC_0twsg98Jgwkf6oKJgThZhkpPIEohpR0M4b970shNd09uuHsHKFqJ4EOpRVexJOWqtw83ZIiS3dKEK0YV3K-iRLbMuUIluQqY5x1Y6HSV_yFysCYIJ4gdbGY4OtgSRBOcHOxmODvYE8ACGtSNqCXdOPwu4WAqbJCDT60U-sWBq5H2hDVt9lEF-EZbXIBubVmB_xTvnibbSWEwrgX91syKsjatvrgIpiTGL-8RVcQ)

### Depth-First Crawling

![Flowchart showing a Seed URL leading to Page 1, then to Page 2. Page 2 connects to Page 3, which branches to Page 4 and Page 5.](https://mermaid.ink/svg/pako:eNo9zz0PgjAQBuC_0twsg18LgwlfGyYG4uQ5VHoC0RZS2sEQ_rsnTezU98mlvXeGZlAEMbRWjp0oKzSTf4RQEylxrUo0gk9yu8iWxPaOhoxCk4goOok06I41XSELsGfIVsgDHBjyFYoAR4YivCEEGtiAJqtlr3iZ-fclgutIE0LMVyXtCwHNwnPSu6H-mAZiZz1twA6-7SB-yvfEyY9KOsp7ySX0X0n1brDn0HWtvHwB2SFOww)



## Extracting Valuable Information
- `Links (Internal and External)`: These are the fundamental building blocks of the web, connecting pages within a website (`internal links`) and to other websites (`external links`). Crawlers meticulously collect these links, allowing you to map out a website's structure, discover hidden pages, and identify relationships with external resources.
- `Comments`: Comments sections on blogs, forums, or other interactive pages can be a goldmine of information. Users often inadvertently reveal sensitive details, internal processes, or hints of vulnerabilities in their comments.
- `Metadata`: Metadata refers to `data about data`. In the context of web pages, it includes information like page titles, descriptions, keywords, author names, and dates. This metadata can provide valuable context about a page's content, purpose, and relevance to your reconnaissance goals.
- `Sensitive Files`: Web crawlers can be configured to actively search for sensitive files that might be inadvertently exposed on a website. This includes `backup files` (e.g., `.bak`, `.old`), `configuration files` (e.g., `web.config`, `settings.php`), `log files` (e.g., `error_log`, `access_log`), and other files containing passwords, `API keys`, or other confidential information. Carefully examining the extracted files, especially backup and configuration files, can reveal a trove of sensitive information, such as `database credentials`, `encryption keys`, or even source code snippets.

