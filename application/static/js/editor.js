(function ($) {
	jQuery.fn.editor = function(options) {
		if (options === undefined) {
			options = {};
		}

		var notes = [];
		
		//Interface positions in pixels
		var notesPointZero = 182;
		var halfTonePosition = 7;
		var CursorInterval = 56;
		var UpperStaffLineStep = 10;
		var LowerStaffLineStep = 2;
		
		// X-coordinate of staff beginning
		var left0 = 60;
		// The most left X-coordinate of cursor
		var cursoreLeft0 = left0;
		// X-coordinate of the first note
		var notesLeft0 = left0 + 25;

		function GetNoteFromY(y) {
			var StaffSteps = (notesPointZero - y)/halfTonePosition;
			
			var Octave = Math.floor(StaffSteps/7);
			var NotePos = StaffSteps % 7;
			if (NotePos < 0) {
				NotePos = NotePos + 7;
			}
			
			return {
				octave: Octave,
				notePos: NotePos,
				staffSteps: StaffSteps
			}
		}

		function DisplayNote(noteElement, staffSteps) {
			if (staffSteps > UpperStaffLineStep) {
				noteElement.addClass('lined');
				var LineElement = noteElement.find('.line');
				LineElement.css('height', (14+(staffSteps-UpperStaffLineStep)*7)+'px');
				if (staffSteps & 1) {
					LineElement.css('top', '45px');
				}
				else {
					LineElement.css('top', '38px');
				}
			}
			else if (staffSteps < LowerStaffLineStep) {
				noteElement.addClass('lined');
				var LineElement = noteElement.find('.line');
				var DeltaHeight = (LowerStaffLineStep-staffSteps-2)*7;
				LineElement.css('height', (20+DeltaHeight)+'px');
				LineElement.css('top', (24-DeltaHeight)+'px');
				LineElement.css('background-position-y', '0px');
			}
			else {
				noteElement.removeClass('lined');
			}
		}

		return this.each(function() {
			function DeselectAllnotes() {
				$('.note').removeClass('selected');
			}
			
			function GetSelectedNote(Elem) {
				if (Elem == null) {
					Elem = musicStaff.find('.note.selected').eq(0);
				}
				
				var NoteIndex = parseInt(Elem.find('input[name="index"]').eq(0).val());
				return {
					elem: Elem,
					index: NoteIndex
				}
			}
			
			function DisableNoteAttributesToolbar() {
				var NoteAttrToolbar = Toolbar.find('.note_attributes').eq(0);
				NoteAttrToolbar.find('input').prop('disabled', true);
				
				Toolbar.find('.delete_note').eq(0).prop('disabled', true);
			}
			
			function EnableNoteAttributesToolbar(name) {
				var NoteAttrToolbar = Toolbar.find('.note_attributes').eq(0);
				if (name) {
					NoteAttrToolbar.find('input[name="'+name+'"]').prop('disabled', false);
				}
				else {
					NoteAttrToolbar.find('input').prop('disabled', false);
				}
				
				Toolbar.find('.delete_note').eq(0).prop('disabled', false);
			}
			
			function LoadNotePropertiesToToolbar(elem) {
				var SelectedNote = GetSelectedNote(elem);
				
				var note = notes[SelectedNote.index];
				
				if (note.elementType == 'note') {
					EnableNoteAttributesToolbar();
					var NoteAttrToolbar = Toolbar.find('.note_attributes').eq(0);
					
					// alteration
					if (note.alter == 'bemol') {
						NoteAttrToolbar.find('label.checkbox_button input[name="bemol"]').prop('checked', true);
						NoteAttrToolbar.find('label.checkbox_button input[name="sharp"]').prop('checked', false);
					}
					else if (note.alter == 'sharp') {
						NoteAttrToolbar.find('label.checkbox_button input[name="bemol"]').prop('checked', false);
						NoteAttrToolbar.find('label.checkbox_button input[name="sharp"]').prop('checked', true);
					}
					else {
						NoteAttrToolbar.find('label.checkbox_button input[name="bemol"]').prop('checked', false);
						NoteAttrToolbar.find('label.checkbox_button input[name="sharp"]').prop('checked', false);
					}
					
					// dotted
					if (note.dotted == true) {
						NoteAttrToolbar.find('label.checkbox_button input[name="dotted"]').prop('checked', true);						
					}
					else {
						NoteAttrToolbar.find('label.checkbox_button input[name="dotted"]').prop('checked', false);						
					}
				}
				else if (note.elementType == 'rest') {
					EnableNoteAttributesToolbar('dotted');
					var NoteAttrToolbar = Toolbar.find('.note_attributes').eq(0);

					// dotted
					if (note.dotted == true) {
						NoteAttrToolbar.find('label.checkbox_button input[name="dotted"]').prop('checked', true);						
					}
					else {
						NoteAttrToolbar.find('label.checkbox_button input[name="dotted"]').prop('checked', false);						
					}
				}
				else {
					DisableNoteAttributesToolbar();
				}
			}

			function SelectNote(note) {
				DeselectAllnotes();
				note.addClass('selected');
				LoadNotePropertiesToToolbar(note);
			}
			
			// Set note element position
			function SetNoteElementPosition(elem, pos) {
				var NewX = notesLeft0 + pos*CursorInterval;
				elem.find('input[name="index"]').eq(0).val(pos);
				elem.css('left', NewX+'px');
			}
			
			// Return note ID.
			// Note with ID = 0 is C in the 0th octave.
			// ID = 1 is C# in the 0th octave,
			// ID = 2 is D in the 0th octave,
			// ID = -1 is B in the -1st octave etc.
			function GetNoteID(note, clef) {
				if (clef == null) {
					clef = 'treble';
				}
				
				// notePosInOctave: noteIdInOctave
				var noteIDs = {
					0: 0, // C
					1: 2, // D
					2: 4, // E
					3: 5, // F
					4: 7, // G
					5: 9, // A
					6: 11 // B
				}
				
				var Ret = note.octave*12 + noteIDs[note.notePos];
				
				if (note.alter == 'sharp') {
					Ret = Ret + 1;
				}
				else if (note.alter == 'bemol') {
					Ret = Ret - 1;
				}
				
				return Ret;
			}
			
			// Return note by note ID
			function GetNoteByID(noteID) {
				var octave = Math.floor(noteID/12);
				
				var octaveNoteID = noteID % 12;
				if (octaveNoteID < 0) {
					octaveNoteID = octaveNoteID + 12;
				}
				
				// Get staff steps and alteration
				var notesByID = {
					0: {notePos: 0, alter: ''},
					1: {notePos: 0, alter: 'sharp'},
					2: {notePos: 1, alter: ''},
					3: {notePos: 2, alter: 'bemol'},
					4: {notePos: 2, alter: ''},
					5: {notePos: 3, alter: ''},
					6: {notePos: 3, alter: 'sharp'},
					7: {notePos: 4, alter: ''},
					8: {notePos: 4, alter: 'sharp'},
					9: {notePos: 5, alter: ''},
					10: {notePos: 6, alter: 'bemol'},
					11: {notePos: 6, alter: ''}
				};
				
				var Ret = notesByID[octaveNoteID];
				Ret['octave'] = octave;
				Ret['staffSteps'] = octave*7 + Ret.notePos;
				
				return Ret;
			}


			// Add note element
			function AddNoteElement(pos, options) {
				// New note element position
				var NewX = notesLeft0 + pos*CursorInterval;
				var NewY = notesPointZero - options.staffSteps*halfTonePosition;
				
				var DottedClass = '';
				if (options.dotted == true) {
					DottedClass = 'dotted';
				}
				
				var noteElemClass = 'note ';
				if (options.elementType == 'rest') {
					noteElemClass = noteElemClass + 'rest ';
				}
				
				var NewNote = $(
					'<div class="'+noteElemClass+options.elementType+options.duration+' '+options.alter+' '+DottedClass+'">'
						+ '<input type="hidden" name="index" value="' + pos + '"/>'
						+ '<div class="alteration"></div>'
						+ '<div class="dot"></div>'
						+ '<div class="line"></div>'
					+ '</div>'
					);
				NewNote.css('left', NewX+'px');
				NewNote.css('top', NewY+'px');
				musicStaff.append(NewNote);

				if (options.elementType == 'note') {
					DisplayNote(NewNote, options.staffSteps);
					
					NewNote.draggable({
						grid: [CursorInterval, halfTonePosition],
						containment: musicStaff,
						scroll: false,
						axis: "y",
						cursor: "move",
						start: function() {
							SelectNote($(this));
						},
						drag: function(event, ui) {
							var p = ui.position;
							var Note = GetNoteFromY(p.top);
							
							DisplayNote($(this), Note.staffSteps);
						},
						stop: function(event, ui) {
							var noteIndex = parseInt($(this).find('input[name="index"]').eq(0).val());
							var note = GetNoteFromY(parseInt($(this).css('top')));
							notes[noteIndex].staffSteps = note.staffSteps;
							notes[noteIndex].octave = note.octave;
							notes[noteIndex].notePos = note.notePos;
						}
					});
				}

				NewNote.click(function() {
					SelectNote($(this));
					return false;
				});

				return NewNote;
			}
			
			function DeleteNoteElement(elem) {
				if (elem.hasClass('selected')) {
					DisableNoteAttributesToolbar();
				}

				elem.remove();
			}
			
			// Shift a note element horizontally
			function ShiftNoteElement(elem, shiftValue) {
				var NoteIndexElement = elem.find('input[name="index"]').eq(0);
				var NewNoteIndex = parseInt(NoteIndexElement.val()) + shiftValue;
				SetNoteElementPosition(elem, NewNoteIndex);
			}


			// Add note to position
			function AddNote(pos, options) {
				if (pos == null) {
					pos = notes.length;
				}
				
				if (pos > notes.length) {
					pos = notes.length;
				}
				
				// Default options
				Options = {
					elementType: 'note',
					octave: 0,
					notePos: 4,
					staffSteps: 4,
					duration: 8,
					alter: '',
					dotted: false
				};
				$.extend(Options, options);
				
				notes.splice(pos, 0, {
					elementType: Options.elementType,
					octave: Options.octave,
					staffSteps: Options.staffSteps,
					notePos: Options.notePos,
					duration: Options.duration,
					alter: Options.alter,
					dotted: Options.dotted,
					elem: AddNoteElement(pos, Options)
				});

				// Shif note elements
				for (var i = pos + 1; i < notes.length; i++) {
					ShiftNoteElement(notes[i].elem, 1);
				};
			}
			
			function DeleteNote(pos) {
				if (pos == null) {
					return;
				}
				
				if ((pos >= notes.length)||(pos < 0)) {
					return;
				}
				
				DeleteNoteElement(notes[pos].elem);
				notes.splice(pos, 1);
				
				// Shift note elements
				for (var i = pos; i < notes.length; i++) {
					ShiftNoteElement(notes[i].elem, -1);
				};
			}

			function ProcessNoteElement(noteIndex) {
				var NewY = notesPointZero - notes[noteIndex].staffSteps*halfTonePosition;
				notes[noteIndex].elem.css('top', NewY+'px');
				
				notes[noteIndex].elem.removeClass('sharp');
				notes[noteIndex].elem.removeClass('bemol');
				notes[noteIndex].elem.addClass(notes[noteIndex].alter);
			}
			
			
			function CursorOn() {
				Cursor.addClass('on');
			}
			
			function GetCursorPosition() {
				return parseInt(Cursor.find('input[name="position"]').eq(0).val());
			}
			
			function SetCursorPosition(pos) {
				var cursorX = cursoreLeft0 + CursorInterval*pos;
				Cursor.find('input[name="position"]').eq(0).val(pos);
				Cursor.css('left', cursorX+'px');
			}
			
			function AddNoteAtCursor(options) {
				var cursorPosition = GetCursorPosition();
				CursorOn();
				AddNote(cursorPosition, options);
				SetCursorPosition(cursorPosition+1);
			}
			
			function DeleteSelectedNote() {
				var CurNote = GetSelectedNote();
				if (CurNote['index'] !== null) {
					DeleteNote(CurNote['index']);
				}
			}

			function DeleteNoteAtCursor() {
				var cursorPosition = GetCursorPosition();
				DeleteNote(cursorPosition);
				SetCursorPosition(cursorPosition);
			}

			// Return melody object
			function GetMelodyObject() {
				var Ret = {
					"meta": {},
					"notes": []
				};
				for (var i = 0; i < notes.length; i++) {
					Ret["notes"].push({});
					Ret["notes"][i]['element_type'] = notes[i].elementType;
					Ret["notes"][i]['octave'] = notes[i].octave;
					Ret["notes"][i]['staffSteps'] = notes[i].staffSteps;
					Ret["notes"][i]['notePos'] = notes[i].notePos;
					Ret["notes"][i]['duration'] = notes[i].duration;
					Ret["notes"][i]['alter'] = notes[i].alter;
					Ret["notes"][i]['dotted'] = notes[i].dotted;
					Ret["notes"][i]['note_id'] = GetNoteID(notes[i]);
				}
				return Ret;
			}
			
			// Return note in abc notation
			function GetNoteABC(note, isFlat) {
				var notestr = '';
				
				if (note.elementType == 'note') {
					// Alteration
					if (note.alter == 'sharp') {
						notestr = notestr + '^';
					}
					else if (note.alter == 'bemol') {
						notestr = notestr + '_';
					}
					else if (isFlat) {
						notestr = notestr + '=';
					}

					
					// Note letter
					var NoteLetter = {
						0: 'C',
						1: 'D',
						2: 'E',
						3: 'F',
						4: 'G',
						5: 'A',
						6: 'B'
					};
					notestr = notestr + NoteLetter[note.notePos];
					
					// Octave
					if (note.octave > 0) {
						for (var j = 0; j < note.octave; j++) {
							notestr = notestr + "'";
						}
					}
					else if (note.octave < 0) {
						for (var j = 0; j < -note.octave; j++) {
							notestr = notestr + ",";
						}
					}
				}
				else if (note.elementType == 'rest') {
					notestr = notestr + 'z';
				}
				
				// Note duration
				if (note.dotted) {
					notestr = notestr + '3/' + note.duration*2;
				}
				else {
					notestr = notestr + '/' + note.duration;
				}
				
				return notestr;
			}
			

			// Chooses note symbol (4th, 8th etc.) and dot presence by note duration (e.g. 0.125 is a 8th note).
			function ChooseNoteDuration(note_duration) {
				var durations = [
					{duration: 0.031250, note_duration: 32, dotted: false},
					{duration: 0.046875, note_duration: 32, dotted: true},
					{duration: 0.062500, note_duration: 16, dotted: false},
					{duration: 0.093750, note_duration: 16, dotted: true},
					{duration: 0.125000, note_duration: 8, dotted: false},
					{duration: 0.187500, note_duration: 8, dotted: true},
					{duration: 0.250000, note_duration: 4, dotted: false},
					{duration: 0.375000, note_duration: 4, dotted: true},
					{duration: 0.500000, note_duration: 2, dotted: false},
					{duration: 0.750000, note_duration: 2, dotted: true},
					{duration: 1.000000, note_duration: 1, dotted: false},
					{duration: 1.500000, note_duration: 1, dotted: true}
				];

				if (note_duration < durations[0]['duration']) {
					return durations[0];
				}
				else if (note_duration > durations[durations.length - 1]['duration']) {
					return durations[durations.length - 1];
				}
				else {
					for (var i = 0; i < durations.length; i++) {
						if (note_duration == durations[i]['duration']) {
							return durations[i];
						}
						else if (note_duration < durations[i]['duration']) {
							if (note_duration < (durations[i]['duration'] + durations[i-1]['duration'])/2) {
								return durations[i-1];
							}
							else {
								return durations[i];
							}
						}
					}
				}
			}
			
			// Clear editor
			function ClearEditor() {
				for (var i = 0; i < notes.length; i++) {
					notes[i].elem.remove();
				}
				while (notes.length > 0) {
					notes.pop();
				}			
				SetCursorPosition(0);
			}
			
			var methods = {
				// Return melody in JSON 
				getJSON: function() {
					return JSON.stringify(GetMelodyObject());
				},
				
				// Clear editor
				clear: function() {
					return ClearEditor();
				},
				
				// Return melody in abc notation
				getABC: function() {
					var Ret = ''
						+ 'X: 1\n'
						+ 'M: 8/8\n'
						+ 'L: 1/1\n'
						+ 'K: Cmaj\n'
					;
					
					// Splitting melody into lines 16 notes each
					var notesLine = '';
					var notesCount = 0;

					// For saving alterations
					var alterations = {};

					for (var i = 0; i < notes.length; i++) {
						var isFlat = false;
						if (notes[i].elementType == 'note') {
							// Saving alteration
							if (notes[i].alter != "") {
								alterations[notes[i].notePos + ' : ' + notes[i].octave] = notes[i].alter;
							}
							// Adding 'flat'
							else if (alterations[notes[i].notePos + ' : ' + notes[i].octave]) {
								isFlat = true;
								delete alterations[notes[i].notePos + ' : ' + notes[i].octave];
							}
						}

						var notestr = GetNoteABC(notes[i], isFlat);

						notesLine = notesLine + notestr + ' ';
						
						notesCount = notesCount + 1;
						
						if (notesCount >= 16) {
							Ret = Ret + notesLine + '\n';
							var notesLine = '';
							notesCount = 0;
						}
					}
					
					if (notesLine != '') {
						Ret = Ret + notesLine + '\n';
					}
					
					return Ret;
				},
				
				// Import melody from JSON
				importFromJSONString: function(jsonStr) {
					try {
						var obj = JSON.parse(jsonStr);

						ClearEditor();
						
						for (var i = 0; i < obj['notes'].length; i++) {
							var noteObj = {};
							
							if (obj['notes'][i]['element_type'] == 'note') {
								var note = GetNoteByID(obj['notes'][i]['note_id']);

								noteObj['elementType'] = 'note';
								noteObj['octave'] = note['octave'];
								noteObj['staffSteps'] = note['staffSteps'];
								noteObj['notePos'] = note['notePos'];

								if ((obj['notes'][i]['duration'] != null) && (obj['notes'][i]['dotted'] != null)) {
									noteObj['duration'] = obj['notes'][i]['duration'];
									noteObj['dotted'] = obj['notes'][i]['dotted'];
								}
								else {
									var noteDurationObj = ChooseNoteDuration(obj['notes'][i]['duration_float']);
									noteObj['duration'] = noteDurationObj['note_duration'];
									noteObj['dotted'] = noteDurationObj['dotted'];
								}

								noteObj['alter'] = note['alter'];
								noteObj['note_id'] = obj['notes'][i]['note_id'];
								AddNote(i, noteObj);
								
							}
							else if (obj['notes'][i]['element_type'] == 'rest') {
								if ((obj['notes'][i]['duration'] != null) && (obj['notes'][i]['dotted'] != null)) {
									noteObj['duration'] = obj['notes'][i]['duration'];
									noteObj['dotted'] = obj['notes'][i]['dotted'];
								}
								else {
									var noteDurationObj = ChooseNoteDuration(obj['notes'][i]['duration_float']);
									noteObj['duration'] = noteDurationObj['note_duration'];
									noteObj['dotted'] = noteDurationObj['dotted'];
								}
								noteObj['elementType'] = 'rest';
								AddNote(i, noteObj);
							}
						}
						return true;
					}
					catch (e) {
						return false;
					}
				}
			};
			
			$.fn.func = function(method, params) {
				if (methods[method]) {
					return methods[method](params);
				}
			}
			
			// Creating note sheet and cursor
			var musicStaff = $('<div></div>');
			var Cursor = $('<div class="cursor"><input type="hidden" name="position" value="0"/></div>');
			musicStaff.append(Cursor);

			musicStaff.append('<div class="clef treble"></div>');

			messages = {
				'deleteButtonTitle': 'Usuń wybrany symbol',
				'insertNote': 'Wstaw nutę',
				'insertRest': 'Wstaw pauzę',
				'onOffFlat': 'Wstaw/usuń bemol',
				'onOffSharp': 'Wstaw/usuń krzyżyk',
				'onOffDotted': 'Wstaw/usuń kropkę',
			};
			
			// Creating toolbar
			var Toolbar = $(''
				+ '<div class="toolbar">'
					+ '<div class="panel">'
						+ '<button class="delete_note" title="'+messages['deleteButtonTitle']+'"></button>'
						+ '<button class="add_note add_note_1" title="'+messages['insertNote']+'"></button>'
						+ '<button class="add_note add_note_2" title="'+messages['insertNote']+'"></button>'
						+ '<button class="add_note add_note_4" title="'+messages['insertNote']+'"></button>'
						+ '<button class="add_note add_note_8" title="'+messages['insertNote']+'"></button>'
						+ '<button class="add_note add_note_16" title="'+messages['insertNote']+'"></button>'
						+ '<button class="add_note add_note_32" title="'+messages['insertNote']+'"></button>'
						+ '<button class="add_note add_rest_1" title="'+messages['insertRest']+'"></button>'
						+ '<button class="add_note add_rest_2" title="'+messages['insertRest']+'"></button>'
						+ '<button class="add_note add_rest_4" title="'+messages['insertRest']+'"></button>'
						+ '<button class="add_note add_rest_8" title="'+messages['insertRest']+'"></button>'
						+ '<button class="add_note add_rest_16" title="'+messages['insertRest']+'"></button>'
						+ '<button class="add_note add_rest_32" title="'+messages['insertRest']+'"></button>'
					+ '</div>'
					+ '<div class="panel note_attributes">'
						+ '<label class="checkbox_button"><input name="bemol" type="checkbox"/><div class="button bemol" title="'+messages['onOffFlat']+'"></div></label>'
						+ '<label class="checkbox_button"><input name="sharp" type="checkbox"/><div class="button sharp" title="'+messages['onOffSharp']+'"></div></label>'
						+ '<label class="checkbox_button"><input name="dotted" type="checkbox"/><div class="button dot" title="'+messages['onOffDotted']+'"></div></label>'
					+ '</div>'
					+ '<div class="clear"></div>'
				+ '</div>'
				);
			
			$(this).append(musicStaff);
			$(this).append(Toolbar);

			$(this).addClass('editor');
			musicStaff.addClass('musicStaff');

			SetCursorPosition(notes.length);
			CursorOn();
			DisableNoteAttributesToolbar();
			
			function GetCursorPositionByEvent(e, elem) {
				if (elem == null) {
					elem = musicStaff;
				}

				// Getting mouse coordinates:
				// Note sheet coordinates
				var musicStaffPos = musicStaff.offset();
				// Mouse coordinates
				var mousePos = {
					x: e.pageX - musicStaffPos.left + elem.scrollLeft(),
					y: e.pageY - musicStaffPos.top
				};
				
				var newCursorPosition = Math.round((mousePos.x - cursoreLeft0)/CursorInterval);
				if (newCursorPosition < 0) {
					newCursorPosition = 0;
				}
				else if (newCursorPosition > notes.length) {
					newCursorPosition = notes.length;
				}
				
				return newCursorPosition;
			}
			
			musicStaff.click(function(e) {
				DeselectAllnotes();
				DisableNoteAttributesToolbar();
				
				var cursorPosition = GetCursorPositionByEvent(e);
				
				SetCursorPosition(cursorPosition);
				CursorOn();
			});
			
			// "Add note" buttons
			Toolbar.find('button.add_note_1').click(function() {
				AddNoteAtCursor({duration: 1});
				return false;
			});
			Toolbar.find('button.add_note_2').click(function() {
				AddNoteAtCursor({duration: 2});
				return false;
			});
			Toolbar.find('button.add_note_4').click(function() {
				AddNoteAtCursor({duration: 4});
				return false;
			});
			Toolbar.find('button.add_note_8').click(function() {
				AddNoteAtCursor({duration: 8});
				return false;
			});
			Toolbar.find('button.add_note_16').click(function() {
				AddNoteAtCursor({duration: 16});
				return false;
			});
			Toolbar.find('button.add_note_32').click(function() {
				AddNoteAtCursor({duration: 32});
				return false;
			});
			
			// "Add rest" buttons
			Toolbar.find('button.add_rest_1').click(function() {
				AddNoteAtCursor({elementType: 'rest', duration: 1});
				return false;
			});
			Toolbar.find('button.add_rest_2').click(function() {
				AddNoteAtCursor({elementType: 'rest', duration: 2});
				return false;
			});
			Toolbar.find('button.add_rest_4').click(function() {
				AddNoteAtCursor({elementType: 'rest', duration: 4});
				return false;
			});
			Toolbar.find('button.add_rest_8').click(function() {
				AddNoteAtCursor({elementType: 'rest', duration: 8});
				return false;
			});
			Toolbar.find('button.add_rest_16').click(function() {
				AddNoteAtCursor({elementType: 'rest', duration: 16});
				return false;
			});
			Toolbar.find('button.add_rest_32').click(function() {
				AddNoteAtCursor({elementType: 'rest', duration: 32});
				return false;
			});
			
			// "Delete note" button
			Toolbar.find('button.delete_note').click(function() {
				DeleteSelectedNote();
				return false;
			});
			
			// bemol checkbox
			var cbBemol = Toolbar.find('.note_attributes input[type="checkbox"][name="bemol"]').eq(0);
			// sharp checkbox
			var cbSharp = Toolbar.find('.note_attributes input[type="checkbox"][name="sharp"]').eq(0);
			// dotted checkbox
			var cbDotted = Toolbar.find('.note_attributes input[type="checkbox"][name="dotted"]').eq(0);
			
			// Bemol checkbox
			cbBemol.change(function() {
				var CurNote = GetSelectedNote();
				if ($(this).prop('checked')) {
					CurNote.elem.removeClass('sharp');
					CurNote.elem.addClass('bemol');
					notes[CurNote.index].alter = 'bemol';
				}
				else {
					CurNote.elem.removeClass('bemol');
					notes[CurNote.index].alter = '';
				}
				LoadNotePropertiesToToolbar(CurNote.elem);
			});
			
			// Sharp checkbox
			cbSharp.change(function() {
				var CurNote = GetSelectedNote();
				if ($(this).prop('checked')) {
					CurNote.elem.removeClass('bemol');
					CurNote.elem.addClass('sharp');
					notes[CurNote.index].alter = 'sharp';
				}
				else {
					CurNote.elem.removeClass('sharp');
					notes[CurNote.index].alter = '';
				}
				LoadNotePropertiesToToolbar(CurNote.elem);
			});
			
			// Dotted checkbox
			cbDotted.change(function() {
				var CurNote = GetSelectedNote();
				if ($(this).prop('checked')) {
					CurNote.elem.addClass('dotted');
					notes[CurNote.index].dotted = true;
				}
				else {
					CurNote.elem.removeClass('dotted');
					notes[CurNote.index].dotted = false;
				}
				LoadNotePropertiesToToolbar(CurNote.elem);
			});
			
		});		
	}
}) (jQuery);
