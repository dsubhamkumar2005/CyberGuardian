from pipeline import process_url


test_urls = [

    "https://example.com",

    "https://example.com/login",

    "http://192.168.1.1/login",

    "hello",

    "https://example.com/login"
]


for url in test_urls:

    print("\n========================")
    print("Testing:", url)

    result = process_url(url)

    print(result)