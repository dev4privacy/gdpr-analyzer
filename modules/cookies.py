#!/usr/bin/env python3.7
# coding: utf-8

import time
from datetime import datetime, timedelta
from splinter import Browser


def cookie_expiration(cookies):
    """
    calculate the cookie expiry time for 'url_website'
    and define the number of cookies per duration step
    :param website_url: URL of target to audit
    :return: cookie dictionnary
    """

    tracker_dict = {}
    unlimited_nb = 0
    thirty_month_nb = 0
    eight_month_nb = 0
    six_month_nb = 0
    three_month_nb = 0

    # print(cookies)

    for cookie in cookies:

        # print(cookie)
        # name = cookie["name"]

        try:
            expiry = cookie["expiry"]
            # print(expiry)

            # calculate the expiry time of cookies
            expiration_delay = timedelta(seconds=expiry - now)
            # print(f"Cookie '{name}' expire in : {expiration_delay}")

            # count the number of cookies in each expiry time range
            if expiration_delay.days > 394:  # 13 month
                thirty_month_nb += 1

            elif expiration_delay.days > 240:  # 8 month
                eight_month_nb += 1

            elif expiration_delay.days > 180:  # 6 month
                six_month_nb += 1

            elif expiration_delay.days > 90:  # 3 month
                three_month_nb += 1

        except KeyError:
            unlimited_nb += 1  # no expiration
            # print(f"Cookie '{name}' does not expire")

    # put the counters in the dictionary
    tracker_dict["unlimited"] = unlimited_nb
    tracker_dict["thirty_month"] = thirty_month_nb
    tracker_dict["eight_month"] = eight_month_nb
    tracker_dict["six_month"] = six_month_nb
    tracker_dict["three_month"] = three_month_nb

    return tracker_dict


def third_party_cookies(cookies, website_url):

    tracker_dict = {}
    third_party_nb = 0

    # compute all possible domains for the targeted website
    # and adapt its URL
    if website_url[:5] == "https":
        website_url = website_url[8:]
    else:
        website_url = website_url[7:]

    # print(website_url)

    for cookie in cookies:

        domain = cookie["domain"]

        # count the number of domains which correspond to third parties
        if website_url.find(domain) is False:  # is false useless but better understanding
            third_party_nb += 1

    # put the counter in the dictionary
    tracker_dict["third_party"] = third_party_nb

    return tracker_dict


def cookie_storage(cookies):

    tracker_dict = {}

    return tracker_dict


if __name__ == '__main__':

    website_url = 'https://www.dealabs.com'
    browser = Browser('firefox')  # create temporary profile for the use of our tool
                                    # in order to check the third party cookies

    now = int(time.time())
    print("Current date:", datetime.fromtimestamp(now))

    browser.visit(website_url)
    cookies = browser.cookies.all(verbose=True)
    tracker_dict = cookie_expiration(cookies)
    third_party_cookies = third_party_cookies(cookies, website_url)
    browser.quit()

    print(tracker_dict)
    print(third_party_cookies)
