#!/usr/bin/env python3.7
# coding: utf-8

import time
from datetime import timedelta
import json

import configparser
import os

config = configparser.ConfigParser()
config.read(os.path.dirname(__file__) + '/config.ini')


def cookie_expiration(browsing_time, cookie):
    """
    calculate the cookies expiry time and define
    the number of cookies per duration step in
    order to give a score
    :param cookie: list of session cookies
    :return: expiry_score, expiry_info
    """

    expiry_point = 0

    unlimited_pt = int(config['delay_point']['unlimited'])
    more_thirty_month_pt = int(config['delay_point']['more_thirty_month'])
    thirty_month_pt = int(config['delay_point']['thirty_month'])
    eight_month_pt = int(config['delay_point']['eight_month'])
    six_month_pt = int(config['delay_point']['six_month'])
    three_month_pt = int(config['delay_point']['three_month'])
    one_month_pt = int(config['delay_point']['one_month'])

    try:

        expiry = cookie[7]

        # TODO round to the top minute ?
        expiration_delay = timedelta(seconds=expiry - browsing_time)

        # count the number of cookies in each expiry time range
        if expiration_delay.days > 394:  # + 13 month
            expiry_point = more_thirty_month_pt

        elif expiration_delay.days > 240:  # 8 month < delay < 13 month
            expiry_point += thirty_month_pt

        elif expiration_delay.days > 180:  # 6 month < delay < 8 month
            expiry_point += eight_month_pt

        elif expiration_delay.days > 90:  # 3 month < delay < 6 month
            expiry_point += six_month_pt

        elif expiration_delay.days > 30:  # 1 month < delay < 3 month
            expiry_point += three_month_pt

        else:  # - 1 month
            expiry_point += one_month_pt

    except KeyError:  # no expiration
        expiration_delay = 'unlimited'  # TODO to clean
        expiry_point += unlimited_pt

    return expiration_delay, expiry_point


def third_party_cookie(cookie, website_url):
    """
    calculate the number of third party cookies and
    define a score
    :param cookie: cookie to analyze
    :param website_url: website url to test
    :return: third_party_score, third_party_info
    """

    domain = cookie[1]

    # count the number of domains which correspond to third parties
    if website_url.find(domain) >= 0:
        third_party = 'NO'
        third_party_point = 0
    else:
        third_party = 'YES'
        third_party_point = int(config['third_party']['third_party'])

    return third_party, third_party_point


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


def cookie_evaluate(browsing_time, cookies, target):
    global_cookie_score = 0
    result = {}
    cookie_result = {}
    result['details'] = {}

    for cookie in cookies:
        name = cookie[3]

        # third party analysis
        third_party, third_party_point = third_party_cookie(cookie, target)

        # expiration delay analysis
        expiration_delay, expiry_point = cookie_expiration(browsing_time, cookie)

        # score for the cookie in the loop
        cookie_score = third_party_point + expiry_point

        # add cookie to json
        result['details'][name] = {
            'third_party': third_party,
            'expiry': str(expiration_delay),
            'cookie_score': cookie_score
        }

        # score for all cookies
        global_cookie_score += cookie_score

    # grade for cookies
    cookie_grade = calculate_grade(global_cookie_score)

    # add cookie grade and score in json
    result['grade'] = cookie_grade
    result['score'] = global_cookie_score

    cookie_result['cookies'] = result
    cookie_result = json.dumps(cookie_result, indent=4)
    #print(cookie_result)
    return cookie_result
