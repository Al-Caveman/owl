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

import_ok = True
import re
try:
    import weechat
except ImportError:
    print('This script must be run under WeeChat.')
    print('Get WeeChat now at: http://www.weechat.org/')
    import_ok = False

# script options
owl_settings_default = {
    'staffers': (
        '.*!~.*@.*staff.*',
        'matching pattern for identifying preying staffers in channels.'),
    'channels_on': (
        '',
        'comma separated list of network.channels where owl is active.'),
    'channels_off': (
        '',
        'comma separated list of network.channels where owl is inactive.'),
    'channels_default': (
        'on',
        'whether owl is active by default, unless overwritten by channels_on or channels_off.  either "on" or "off".'),
    'alert_bg_color': (
        'darkred',
        'background color the input field when a preying staffer is detected in the buffer'),
    'alert_fg_color': (
        'white',
        'foreground color the input field when a preying staffer is detected in the buffer'),
}

# global variables 
owl_settings = {}
owl_state = {}
owl_on = set()
owl_off = set()
owl_default_on = False
owl_staffers_re = None

def optimize_configs():
    global owl_default_on
    global owl_staffers_re
    if owl_settings['channels_default'] == 'on':
        owl_default_on = True
    for i in owl_settings['channels_off'].split(','):
        owl_off.add(i)
    for i in owl_settings['channels_on'].split(','):
        owl_on.add(i)
    owl_staffers_re = re.compile(owl_settings['staffers'])

def owl_init():
    # check every buffer
    ilb = weechat.infolist_get('buffer', '', '')
    while weechat.infolist_next(ilb):
        buff_ptr = weechat.infolist_pointer(ilb, 'pointer')
        buff_name = weechat.infolist_string(ilb, 'name')
        buff_server = weechat.buffer_get_string(buff_ptr, 'localvar_server')
        buff_channel = weechat.buffer_get_string(buff_ptr, 'localvar_channel')

        if DEBUG:
            weechat.prnt( '', 'ptr:{} name:{}\n'.format(buff_ptr, buff_name))

        # is owl active in this channel?
        if (
            buff_name in owl_on
            or (buff_name not in owl_off and owl_default_on)
        ):
            # analyze nicks in the buffer
            iln = weechat.infolist_get(
                'irc_nick', '', '{},{}'.format(buff_server, buff_channel)
            )
            while weechat.infolist_next(iln):
                nick_ptr = weechat.infolist_pointer(iln, 'pointer')
                nick_name = weechat.infolist_string(iln, 'name')
                nick_host = weechat.infolist_string(iln, 'host')
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
        optimize_configs()
        owl_init()

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
