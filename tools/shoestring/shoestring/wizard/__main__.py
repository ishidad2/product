import asyncio
import gettext
import os

from prompt_toolkit import Application
from prompt_toolkit.filters.base import Condition
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.layout.containers import ConditionalContainer, HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.widgets import Label
from prompt_toolkit.widgets.toolbars import ValidationToolbar
from zenlog import log

from shoestring.__main__ import main as shoestring_main
from shoestring.wizard.ShoestringOperation import requires_ca_key_path

from . import keybindings, navigation, styles
from .screen_loader import load_screens, lookup_screens_list_for_operation
from .Screens import Screens
from .shoestring_dispatcher import dispatch_shoestring_command
from .TitleBar import TitleBar


async def main():  # pylint: disable=too-many-locals, too-many-statements
	lang = gettext.translation('messages', localedir='lang', languages=(os.environ.get('LC_MESSAGES', 'en'), 'en'))
	lang.install()

	key_bindings = keybindings.initialize()
	app_styles = styles.initialize()
	navbar = navigation.initialize()

	screens = Screens(navbar)
	load_screens(screens)

	main_container = screens.current
	root_container = HSplit([
		# note: we can use this titlebar to show where are we in the wizard
		Label(style='class:titlebar', text=HTML('')),
		Window(height=1, char='-'),

		main_container,
		ValidationToolbar(),

		ConditionalContainer(
			Window(
				FormattedTextControl('one or more inputs have errors that need fixing'),
				height=1,
				style='class:validation-toolbar'
			),
			filter=Condition(lambda: not screens.current.is_valid()),
		),

		ConditionalContainer(
			navbar.container,
			filter=Condition(lambda: not screens.current.hide_navbar),
		),
	])
	navbar.next.state_filter = Condition(lambda: not screens.current.is_valid())

	title_bar = TitleBar(root_container.children[0].content)

	layout = Layout(root_container, focused_element=navbar.next)

	app = Application(layout, key_bindings=key_bindings, style=app_styles, full_screen=True)

	layout.focus(root_container.children[2])

	# set navigation bar button handlers

	def next_clicked():
		next_screen = screens.next()
		root_container.children[2] = next_screen
		title_bar.update_navigation(screens)

		if 'end-screen' != screens.ordered[screens.current_id].screen_id:
			if hasattr(next_screen, 'reset'):
				next_screen.reset()

			layout.focus(next_screen)
		else:
			operation = screens.get('welcome').operation
			allowed_screens_list = lookup_screens_list_for_operation(screens, operation)

			tokens = []
			for screen_id in allowed_screens_list:
				screen = screens.get(screen_id)
				if hasattr(screen, 'tokens'):
					tokens.extend(screen.tokens)

			next_screen.clear()
			for token in tokens:
				next_screen.add_setting(*token)

			# generate_settings() will go here
			navbar.next.text = _('wizard-button-finish')
			navbar.next.handler = app.exit

	def prev_clicked():
		if screens.has_previous:
			root_container.children[2] = screens.previous()
			title_bar.update_navigation(screens)
		else:
			title_bar.reset()

		# restore handler in case it got replaced
		navbar.next.handler = next_clicked
		navbar.next.text = _('wizard-button-next')

	navbar.prev.handler = prev_clicked
	navbar.next.handler = next_clicked

	# set welcome screen button handlers
	def create_button_handler(button):
		def button_handler():
			allowed_screens_list = lookup_screens_list_for_operation(screens, button.operation)
			screens.set_list(allowed_screens_list)
			next_clicked()

			screens.current.require_ca_pem_path(requires_ca_key_path(button.operation))
			screens.get('welcome').select(button)

		return button_handler

	for button in screens.get('welcome').buttons:
		button.handler = create_button_handler(button)

	result = await app.run_async()

	# second condition is temporarily added, to break processing when ctrl-q or ctrl-c is pressed
	if result or navbar.next.text != _('wizard-button-finish'):
		return

	# TODO: temporary here, move up
	await dispatch_shoestring_command(screens, shoestring_main)

	log.info(_('wizard-main-done'))


if '__main__' == __name__:
	asyncio.run(main())
