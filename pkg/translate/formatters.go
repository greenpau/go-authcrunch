// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package translate

import (
	"fmt"
	"time"
)

// FormatTimestamp translates a field label and appends a localized date/time string.
func FormatTimestamp(fieldID string, timestamp string, langID LangID) string {
	parsedTime, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return fmt.Sprintf("%s: %s", fieldID, timestamp)
	}

	fieldLabel := Translate(fieldID, langID, nil)
	localizedDate := formatLocalizedDate(parsedTime, langID)
	return fmt.Sprintf("%s: %s", fieldLabel, localizedDate)
}

func formatLocalizedDate(t time.Time, langID LangID) string {
	switch langID {
	case French:
		weekdays := []string{"dimanche", "lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi"}
		months := []string{
			"janvier", "février", "mars", "avril", "mai", "juin",
			"juillet", "août", "septembre", "octobre", "novembre", "décembre",
		}
		return fmt.Sprintf("%s %d %s %d %02d:%02d",
			weekdays[int(t.Weekday())], t.Day(), months[int(t.Month())-1], t.Year(), t.Hour(), t.Minute())

	case German:
		weekdays := []string{"Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"}
		months := []string{
			"Januar", "Februar", "März", "April", "Mai", "Juni",
			"Juli", "August", "September", "Oktober", "November", "Dezember",
		}
		return fmt.Sprintf("%s, %d. %s %d %02d:%02d",
			weekdays[int(t.Weekday())], t.Day(), months[int(t.Month())-1], t.Year(), t.Hour(), t.Minute())

	case Japanese:
		weekdays := []string{"日", "月", "火", "水", "木", "金", "土"}
		return fmt.Sprintf("%d年%d月%d日(%s) %02d:%02d",
			t.Year(), t.Month(), t.Day(), weekdays[int(t.Weekday())], t.Hour(), t.Minute())

	case Chinese:
		weekdays := []string{"日", "一", "二", "三", "四", "五", "六"}
		return fmt.Sprintf("%d年%d月%d日 星期%s %02d:%02d",
			t.Year(), t.Month(), t.Day(), weekdays[int(t.Weekday())], t.Hour(), t.Minute())

	case Russian:
		weekdays := []string{"воскресенье", "понедельник", "вторник", "среда", "четверг", "пятница", "суббота"}
		months := []string{
			"января", "февраля", "марта", "апреля", "мая", "июня",
			"июля", "августа", "сентября", "октября", "ноября", "декабря",
		}
		return fmt.Sprintf("%s, %d %s %d г., %02d:%02d",
			weekdays[int(t.Weekday())], t.Day(), months[int(t.Month())-1], t.Year(), t.Hour(), t.Minute())

	case Hebrew:
		weekdays := []string{"ראשון", "שני", "שלישי", "רביעי", "חמישי", "שישי", "שבת"}
		return fmt.Sprintf("יום %s, %d/%d/%d %02d:%02d",
			weekdays[int(t.Weekday())], t.Day(), int(t.Month()), t.Year(), t.Hour(), t.Minute())

	case Arabic:
		weekdays := []string{"الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت"}
		months := []string{
			"يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو",
			"يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر",
		}
		return fmt.Sprintf("%s، %d %s %d %02d:%02d",
			weekdays[int(t.Weekday())], t.Day(), months[int(t.Month())-1], t.Year(), t.Hour(), t.Minute())
	default:
		// Default (English)
		return t.Format("Monday, January 2, 2006 15:04")
	}
}
