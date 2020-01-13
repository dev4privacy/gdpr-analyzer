#!/usr/bin/env python3.7
# coding: utf-8

import time
from datetime import timedelta
import json

import configparser
import os

config = configparser.ConfigParser()
config.read(os.path.dirname(__file__) + '/config.ini')


def cookie_expiration(cookies):
    """
    calculate the cookies expiry time and define
    the number of cookies per duration step in
    order to give a score
    :param cookies: list of session cookies
    :return: expiry_score, expiry_info
    """

    expiry_score = 0
    expiry_info = {}

    unlimited_nb = 0
    more_thirty_month_nb = 0
    thirty_month_nb = 0
    eight_month_nb = 0
    six_month_nb = 0
    three_month_nb = 0
    one_month_nb = 0

    unlimited_pt = int(config['delay_point']['unlimited'])
    more_thirty_month_pt = int(config['delay_point']['more_thirty_month'])
    thirty_month_pt = int(config['delay_point']['thirty_month'])
    eight_month_pt = int(config['delay_point']['eight_month'])
    six_month_pt = int(config['delay_point']['six_month'])
    three_month_pt = int(config['delay_point']['three_month'])
    one_month_pt = int(config['delay_point']['one_month'])

    # print(cookies)  # debug

    for cookie in cookies:

        # print(cookie)  # debug

        try:
            expiry = cookie["expiry"]
            # print(expiry)  # debug

            # calculate the expiry time of cookies
            now = int(time.time())
            expiration_delay = timedelta(seconds=expiry - now)

            # count the number of cookies in each expiry time range
            if expiration_delay.days > 394:  # + 13 month
                more_thirty_month_nb += 1
                expiry_score += more_thirty_month_pt

            elif expiration_delay.days > 240:  # 8 month < delay < 13 month
                thirty_month_nb += 1
                expiry_score += thirty_month_pt

            elif expiration_delay.days > 180:  # 6 month < delay < 8 month
                eight_month_nb += 1
                expiry_score += eight_month_pt

            elif expiration_delay.days > 90:  # 3 month < delay < 6 month
                six_month_nb += 1
                expiry_score += six_month_pt

            elif expiration_delay.days > 30:  # 1 month < delay < 3 month
                three_month_nb += 1
                expiry_score += three_month_pt

            else:  # - 1 month
                one_month_nb += 1
                expiry_score += one_month_pt

        except KeyError:  # no expiration
            unlimited_nb += 1
            expiry_score += unlimited_pt

    # put the counters in the dictionary
    expiry_info["unlimited"] = unlimited_nb
    expiry_info["more_thirty_month"] = more_thirty_month_nb
    expiry_info["thirty_month"] = thirty_month_nb
    expiry_info["eight_month"] = eight_month_nb
    expiry_info["six_month"] = six_month_nb
    expiry_info["three_month"] = three_month_nb
    expiry_info["one_month"] = one_month_nb

    return expiry_score, expiry_info


def third_party_cookies(cookies, website_url):
    """
    calculate the number of third party cookies and
    define a score
    :param cookies: list of session cookies
    :param website_url: website url to test
    :return: third_party_score, third_party_info
    """

    third_party_score = 0
    third_party_info = {}

    third_party_nb = 0

    # compute all possible domains for the targeted website
    # and adapt its URL
    # TODO consider all possible cases (with www. / website.domain / http: / https:)
    if website_url[:5] == "https":
        website_url = website_url[8:]
    else:
        website_url = website_url[7:]

    # print(website_url)  # debug

    for cookie in cookies:
        # print(cookie)  # debug

        domain = cookie["domain"]

        # count the number of domains which correspond to third parties
        if website_url.find(domain) is False:  # is false useless but better understanding
            third_party_nb += 1
            third_party_score += 10  # TODO replace by config file value

    # put the counter in the dictionary
    third_party_info["number"] = third_party_nb

    return third_party_score, third_party_info


def cookie_score_calculation(expiry_score, third_party_score):
    """
    calculate global score for cookies
    :param expiry_score: score for expiry time of cookies
    :param third_party_score: score for third party cookies
    :return: score
    """

    score = expiry_score + third_party_score

    return score


def calculate_grade(cookie_score):
    """
    calculate the cookies grade for the website
    :param cookie_score: score for cookies
    :return: cookie_grade
    """

    a_grade = int(config['grade']['A'])
    b_grade = int(config['grade']['B'])
    c_grade = int(config['grade']['C'])
    d_grade = int(config['grade']['D'])
    e_grade = int(config['grade']['E'])

    if cookie_score <= a_grade:
        cookie_grade = "A"
    elif cookie_score <= b_grade:
        cookie_grade = "B"
    elif cookie_score <= c_grade:
        cookie_grade = "C"
    elif cookie_score <= d_grade:
        cookie_grade = "D"
    elif cookie_score <= e_grade:
        cookie_grade = "E"
    else:
        cookie_grade = "F"

    return cookie_grade


def json_parser(expiry_score, expiry_info, third_party_score, third_party_info,
                cookie_grade, cookie_score):
    """
    parse the results into json object
    :param expiry_score: score for expiry time of cookies
    :param expiry_info: info for expiry time of cookies
    :param third_party_score: score for third party cookies
    :param third_party_info: info for third party cookies
    :param cookie_score: global score for cookies
    :return: json_cookie
    """

    expiry_dict = {
        'score': expiry_score,
        'info': expiry_info
    }

    third_party_dict = {
        'score': third_party_score,
        'info': third_party_info
    }

    result = {
        'grade': cookie_grade,
        'score': cookie_score,
        'expiry': expiry_dict,
        'third_party': third_party_dict,
    }

    cookie_result = {}
    cookie_result["cookies"] = result
    json_cookie = json.dumps(cookie_result, indent=4)

    return json_cookie


def cookie_evaluate(content_cookies, target):
    expiry_score, expiry_info = cookie_expiration(content_cookies)
    # TODO third party
    third_party_score, third_party_info = third_party_cookies(content_cookies, target)

    cookie_score = cookie_score_calculation(expiry_score, third_party_score)
    cookie_grade = calculate_grade(cookie_score)

    json_cookie = json_parser(expiry_score, expiry_info, third_party_score, third_party_info,
                              cookie_grade, cookie_score)

    return json_cookie
