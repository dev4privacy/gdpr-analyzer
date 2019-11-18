#!/usr/bin/env python3.7
# coding: utf-8

import requests
import time
from datetime import datetime, timedelta

# Note : using requests to look for cookies is not reliable, use splinter instead ?


def cookie_expiration(website_url):

    cookie_dict = {}
    thirty_month_nb = 0
    eight_month_nb = 0
    six_month_nb = 0
    three_month_nb = 0

    now = int(time.time())
    print("Current date:", datetime.fromtimestamp(now))

    response = requests.get(website_url)

    for cookie in response.cookies:
        # display cookie name and expiration delay
        expiration_date = datetime.fromtimestamp(cookie.expires)
        expiration_delay = timedelta(seconds=cookie.expires - now)
        print(f"Cookie '{cookie.name}' expire in : {expiration_delay}")

        # test if cookies are trackers by checking the expiration delay
        if expiration_delay.days > 394:  # 13 month
            print(f"Cookie '{cookie.name}' is clearly a tracker")
        #   tracker_point += 10
            thirty_month_nb += 1

        elif expiration_delay.days > 240:  # 8 month
            print(f"Cookie '{cookie.name}' is very suspicious - maybe a tracker")
        #    tracker_point += 8
            eight_month_nb += 1

        elif expiration_delay.days > 180:  # 6 month
            print(f"Cookie '{cookie.name}' is suspicious - maybe a tracker")
        #    tracker_point += 6
            six_month_nb += 1

        elif expiration_delay.days > 90:  # 3 month
            print(f"Cookie '{cookie.name}' is a little suspicious - maybe a tracker")
        #    tracker_point += 3
            three_month_nb += 1

        else:
            print(f"Cookie '{cookie.name}' is not a tracker")

    cookie_dict["thirty_month"] = thirty_month_nb
    cookie_dict["eight_month"] = eight_month_nb
    cookie_dict["six_month"] = six_month_nb
    cookie_dict["three_month"] = three_month_nb

    return cookie_dict
