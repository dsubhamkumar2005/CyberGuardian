from pipeline import process_url


while True:

    url = input("\nEnter URL (type quit to stop): ")

    if url.lower() == "quit":
        break

    result = process_url(url)

    print("\nProcessed Result:")
    print(result)