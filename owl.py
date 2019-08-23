# -*- coding: utf-8 -*-
#
# Copyright (C) 2019 caveman (https://github.com/al-caveman/owl)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#
# Introduction
#
# The indispensable weechat survival tool against the preying staffers. In many
# cases, such staffers are not even ops. So simply looking for people with "@"
# prefixes will mislead you.
# 
# "The silent dog is more dangerous than the barking one." -- caveman, 2019
# 
# owl allows for colorizing the input field depending on whether there are
# preys lurking in the background in the current buffer, as well as letting you
# list them in the buffer.
#
#
# How does it work?
#
# 1. /owl in a channel to list preys.
# 2. /set owl to configure more stuff.  Here you configure a regular expression
# to match preys.  By default *!~*@*staff* is added (better be safe than
# sorry), and the input field's colour changes upon the existence of preys such
# that its background is dark red, and your input text is yellow.
#
# Happy IRCing, and I wish you survival.
#
#
# History:
#
# 2019-08-14, caveman:
#     v0: initial version

SCRIPT_NAME = 'owl'
SCRIPT_AUTHOR = 'caveman <toraboracaveman@protonmail.com>'
SCRIPT_VERSION = '0'
SCRIPT_LICENSE = 'GPL3'
SCRIPT_DESC = 'Warns you of silent dogs, such as preying network staffers.'

SCRIPT_COMMAND = 'owl'

DEBUG = True
DIR_IN = 0
DIR_OUT = 1
RULES = 5

import_ok = True
import re
import sys
try:
    import weechat
except ImportError:
    print('This script must be run under WeeChat.')
    print('Get WeeChat now at: http://www.weechat.org/')
    import_ok = False

# script options
owl_settings_default = {
    'rule_1_match': (
        '.*!~.*@.*staff.*',
        'python regular expression to match on hostnames for rule 1.'),
    'rule_1_input_bg_on': (
        'default',
        'background color of input bar when owl spotted stuff in the buffer.'),
    'rule_1_input_bg_off': (
        'default',
        'background color of input bar when owl spots nothing there in the buffer.'),
    'rule_1_input_fg_on': (
        'default',
        'foreground color of input bar when owl spotted stuff in the buffer.'),
    'rule_1_input_fg_off': (
        'default',
        'Foreground color of input bar when owl spots nothing there in the buffer.'),
    'rule_1_action_on': (
        '/someCommand...',
        'some command to execute when rule_1_match is matched in a user.'),
    'rule_1_action_off': (
        '/someCommand...',
        'some command to execute when rule_1_match is no longer matched in a user.'),

    'rule_2_match': (
        '',
        'python regular expression to match on hostnames for rule 1.'),
    'rule_2_input_bg_on': (
        'default',
        'background color of input bar when owl spotted stuff in the buffer.'),
    'rule_2_input_bg_off': (
        'default',
        'background color of input bar when owl spots nothing there in the buffer.'),
    'rule_2_input_fg_on': (
        'default',
        'foreground color of input bar when owl spotted stuff in the buffer.'),
    'rule_2_input_fg_off': (
        'default',
        'Foreground color of input bar when owl spots nothing there in the buffer.'),
    'rule_2_action_on': (
        '/someCommand...',
        'some command to execute when rule_2_match is matched in a user.'),
    'rule_2_action_off': (
        '/someCommand...',
        'some command to execute when rule_2_match is no longer matched in a user.'),

    'rule_3_match': (
        '',
        'python regular expression to match on hostnames for rule 1.'),
    'rule_3_input_bg_on': (
        'default',
        'background color of input bar when owl spotted stuff in the buffer.'),
    'rule_3_input_bg_off': (
        'default',
        'background color of input bar when owl spots nothing there in the buffer.'),
    'rule_3_input_fg_on': (
        'default',
        'foreground color of input bar when owl spotted stuff in the buffer.'),
    'rule_3_input_fg_off': (
        'default',
        'Foreground color of input bar when owl spots nothing there in the buffer.'),
    'rule_3_action_on': (
        '/someCommand...',
        'some command to execute when rule_3_match is matched in a user.'),
    'rule_3_action_off': (
        '/someCommand...',
        'some command to execute when rule_3_match is no longer matched in a user.'),

    'rule_4_match': (
        '',
        'python regular expression to match on hostnames for rule 1.'),
    'rule_4_input_bg_on': (
        'default',
        'background color of input bar when owl spotted stuff in the buffer.'),
    'rule_4_input_bg_off': (
        'default',
        'background color of input bar when owl spots nothing there in the buffer.'),
    'rule_4_input_fg_on': (
        'default',
        'foreground color of input bar when owl spotted stuff in the buffer.'),
    'rule_4_input_fg_off': (
        'default',
        'Foreground color of input bar when owl spots nothing there in the buffer.'),
    'rule_4_action_on': (
        '/someCommand...',
        'some command to execute when rule_4_match is matched in a user.'),
    'rule_4_action_off': (
        '/someCommand...',
        'some command to execute when rule_4_match is no longer matched in a user.'),

    'rule_5_match': (
        '',
        'python regular expression to match on hostnames for rule 1.'),
    'rule_5_input_bg_on': (
        'default',
        'background color of input bar when owl spotted stuff in the buffer.'),
    'rule_5_input_bg_off': (
        'default',
        'background color of input bar when owl spots nothing there in the buffer.'),
    'rule_5_input_fg_on': (
        'default',
        'foreground color of input bar when owl spotted stuff in the buffer.'),
    'rule_5_input_fg_off': (
        'default',
        'Foreground color of input bar when owl spots nothing there in the buffer.'),
    'rule_5_action_on': (
        '/someCommand...',
        'some command to execute when rule_5_match is matched in a user.'),
    'rule_5_action_off': (
        '/someCommand...',
        'some command to execute when rule_5_match is no longer matched in a user.'),

    'channels_on': (
        '',
        'comma separated list of network.channels where owl is active.'),
    'channels_off': (
        '',
        'comma separated list of network.channels where owl is inactive.'),
    'channels_default': (
        'on',
        'whether owl is active by default, unless overwritten by channels_on or channels_off.  either "on" or "off".'),
    'userhost_timeout': (
        '300',
        'how long to wait to get userhost responses from server.'),
}

# global variables 
owl_settings = {}
owl_state = {
    'nick_buffs' : {},
    'buff_alerts' : {},
}
owl_on_servers = set()
owl_on_channels = set()
owl_off_channels = set()
owl_default_on = False
owl_match = {}
owl_action = {}

def optimize_configs():
    global owl_default_on
    for rule in range(1, RULES+1):
        owl_match[rule] = re.compile(owl_settings['rule_{}_match'.format(rule)])
        owl_action[rule] = {
            'rule_input_bg_on'  : 'rule_{}_input_bg_on'.format(rule),
            'rule_input_bg_off' : 'rule_{}_input_bg_off'.format(rule),
            'rule_input_fg_on'  : 'rule_{}_input_fg_on'.format(rule),
            'rule_input_fg_off' : 'rule_{}_input_fg_off'.format(rule),
            'rule_action_on'    : 'rule_{}_action_on'.format(rule),
            'rule_action_off'   : 'rule_{}_action_off'.format(rule),
        }
    if owl_settings['channels_default'] == 'on':
        owl_default_on = True
    for i in owl_settings['channels_off'].split(','):
        owl_off_channels.add(i)
    for i in owl_settings['channels_on'].split(','):
        owl_on_channels.add(i)
        owl_on_servers.add(i.split('.')[0])

def owl_buff_switch():
    owl_action_on(rule)

def owl_action_on(rule):
    # get current buffer's name
    buff_name_cur = weechat.buffer_get_string('', 'localvar_server')
    weechat.prnt('', 'buff on: {}'.format(buff_name_cur))

def owl_action_off(rule):
    # get current buffer's name
    buff_name_cur = weechat.buffer_get_string('', 'localvar_server')
    weechat.prnt('', 'buff off: {}'.format(buff_name_cur))

def owl_analyze(nick_name, nick_host, buff_name, direction):
    for rule in sorted(owl_match):
        if owl_match[rule].match('{}!{}'.format(nick_name, nick_host)):
            if direction == DIR_IN:
                if buff_name in owl_state['buff_alerts']:
                    owl_state['buff_alerts'][buff_name] += 1
                else:
                    owl_state['buff_alerts'] = {buff_name : 1}
                if owl_state['buff_alerts'][buff_name] == 0:
                    owl_action_on(rule)
            elif direction == DIR_OUT:
                owl_state['buff_alerts'][buff_name] -= 1
                if owl_state['buff_alerts'][buff_name] == 0:
                    del owl_state['buff_alerts'][buff_name]
                    owl_action_off(rule)
            else:
                weechat.prnt('',
                    'error code:  0xDEADBEEF.  '
                    'this is indeed a very strange error.  '
                    'developer couldn\'t even fathom that this might happen.  '
                    'but apparently he was wrong, as you can attest.  '
                    'plz submit an issue in https://github.com/al-caveman/owl.'
                )
                sys.exit(1)

def owl_userhost_cb(a,b,c):
    if DEBUG:
        weechat.prnt('', 'callback:  {}-{}-{}'.format(a,b,c))
    return weechat.WEECHAT_RC_OK

def owl_init():
    # check every buffer
    ilb = weechat.infolist_get('buffer', '', '')
    while weechat.infolist_next(ilb):
        buff_ptr = weechat.infolist_pointer(ilb, 'pointer')
        buff_name = weechat.infolist_string(ilb, 'name')
        buff_server = weechat.buffer_get_string(buff_ptr, 'localvar_server')
        buff_channel = weechat.buffer_get_string(buff_ptr, 'localvar_channel')
        if DEBUG:
            weechat.prnt('', 'ptr:{} name:{}\n'.format(buff_ptr, buff_name))

        # is owl active in this channel?
        if (
            buff_name in owl_on_channels
            or (buff_name not in owl_off_channels and owl_default_on)
        ):
            # analyze nicks in the buffer
            iln = weechat.infolist_get(
                'irc_nick', '', '{},{}'.format(buff_server, buff_channel)
            )
            while weechat.infolist_next(iln):
                nick_ptr = weechat.infolist_pointer(iln, 'pointer')
                nick_name = weechat.infolist_string(iln, 'name')
                nick_host = weechat.infolist_string(iln, 'host')
                # should we use /userhost to get hostname?
                if len(nick_host) == 0:
                    # track nick-buffer relationship
                    if buff_server in owl_state['nick_buffs']:
                        if nick_name in owl_state['nick_buffs'][buff_server]:
                            owl_state['nick_buffs'][buff_server][nick_name].append(buff_name)
                        else:
                            owl_state['nick_buffs'][buff_server][nick_name] = [buff_name]
                    else:
                        owl_state['nick_buffs'][buff_server] = {
                            nick_name : [buff_name]
                        }
                    # do hookie things
                    weechat.hook_hsignal_send(
                        'irc_redirect_command',
                        {
                            'server': buff_server,
                            'pattern': 'userhost',
                            'signal': 'owl',
                            'string': nick_name,
                            'timeout': owl_settings['userhost_timeout'],
                        }
                    )
                    weechat.hook_signal_send(
                        'irc_input_send',
                        weechat.WEECHAT_HOOK_SIGNAL_STRING,
                        '{};;;;/userhost {}'.format(buff_server, nick_name)
                    )
                    nick_host = '****PENDING****'
                else:
                    owl_analyze(nick_name, nick_host, buff_name, DIR_IN)
                if DEBUG:
                    weechat.prnt( '', '  {}!{}\n'.format(nick_name,nick_host))
            weechat.infolist_free(iln)
    weechat.infolist_free(ilb)

    return weechat.WEECHAT_RC_OK

if __name__ == '__main__' and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,
                        SCRIPT_LICENSE, SCRIPT_DESC, '', ''):
        # set default settings
        for option, value in owl_settings_default.items():
            if weechat.config_is_set_plugin(option):
                owl_settings[option] = weechat.config_get_plugin(option)
            else:
                weechat.config_set_plugin(option, value[0])
                weechat.config_set_desc_plugin(option, value[1])
                owl_settings[option] = value[0]

        # initialize
        weechat.hook_hsignal('irc_redirection_owl_userhost', 'owl_userhost_cb', '')
        optimize_configs()
        owl_init()

        # detect current buffer
        weechat.hook_signal('buffer_switch', 'owl_buff_switch', '')


        # add command
        weechat.hook_command(
            SCRIPT_COMMAND,
            SCRIPT_DESC,
            '',
            '',
            '',
            'owl_init',
            ''
        )
