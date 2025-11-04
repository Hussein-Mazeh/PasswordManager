# confusables

[![GoDoc](https://godoc.org/github.com/Zamiell/confusables?status.svg)](https://pkg.go.dev/github.com/Zamiell/confusables?tab=doc)

Confusables is a library written in [Golang](https://golang.org/) to normalize [Unicode](https://en.wikipedia.org/wiki/Unicode) strings, swapping out any potentially visually confusable characters (e.g. [homoglyphs](https://en.wikipedia.org/wiki/Homoglyph)). It was inspired from a [Python library of the same name](https://github.com/woodgern/confusables).

Normalizing homoglyphs is useful for ensuring username uniqueness, finding malicious fake website names, detecting attempts to get past a profanity filter, and more.

In addition to swapping out homoglyphs, this library also uses [norm](https://godoc.org/golang.org/x/text/unicode/norm) under the hood to normalize strings using [NFD](https://en.wikipedia.org/wiki/Unicode_equivalence), which fixes the problem of there being several Unicode ways to represent the same string. See [this Go blog post](https://blog.golang.org/normalization) for more details.

See [below](#the-unicode-problem-with-uniqueness) on *why* you should use this library to normalize Unicode strings. This library is not a complete solution for avoiding homoglyphs attacks; it is merely an effort to fix the "low hanging fruit". Pull requests are welcome.

<br />

## Usage

```
import (
	"fmt"

	"github.com/Zamiell/confusables"
)

func main() {
	username1 := "Alice" // Uses all ASCII characters, like you would naively expect ("A" is 0x41).
	username2 := "Αlice" // Uses a Greek letter A (0x391).

	fmt.Println("Username 1 contains homoglyphs:", confusables.ContainsHomoglyphs(username1)) // Prints "false"
	fmt.Println("Username 2 contains homoglyphs:", confusables.ContainsHomoglyphs(username2)) // Prints "true"

	fmt.Println("No normalization - Usernames are equal:", username1 == username2) // Prints "false"
	username1 = confusables.Normalize(username1)
	fmt.Println("After normalization - Usernames are equal:", username1 == username2) // Prints "true"
}
```

<br />

## The Unicode Problem with Uniqueness

Most websites and applications enforce case-insensitive username uniqueness. For example, if someone has already created an account with a username of "Alice", then others would be prevented from creating accounts with a username of "alice". This is common sense; allowing that kind of thing would just be confusing for everyone involved. Furthermore, it would be a security risk, because "alice" could impersonate "Alice", allowing for effective [phishing attacks](https://en.wikipedia.org/wiki/Phishing). Good thing for us, enforcing case-insensitive username uniqueness is relatively trivial (e.g. putting a [case-insensitive UNIQUE constraint on a PostgreSQL username column](http://shuber.io/case-insensitive-unique-constraints-in-postgres/), for example).

Unfortunately, enforcing case-insensitive username uniqueness is only the first step. Out of the 1+ million characters that Unicode provides, thousands of them are extremely similar to existing characters. For example, the normal capital A is equal to "0x41", the Greek letter "Α" is equal to "0xce 0x91", and the Cyrillic letter "А" is equal to "0xd0 0x90". This means that the impersonation problem from before has gotten a lot worse. Instead of "alice" impersonating "Alice", we now have "Αlice" (with a Greek letter Α) impersonating "Alice". These look-alike characters are called [homoglyphs](https://en.wikipedia.org/wiki/Homoglyph), and the various homoglyphs for the capital letter A are just the tip of the iceberg.

The naive solution to this problem is to forgo Unicode entirely, allowing only [ASCII](https://en.wikipedia.org/wiki/ASCII) input for usernames. But this is a non-starter for any modern project. Even if your website or application is written in English, you can still probably expect to have users from around the world. Japanese users will want to use kanji, Russian users will want to use Cyrillic, and so forth.

Naturally, the people at [The Unicode Consortium](https://en.wikipedia.org/wiki/Unicode_Consortium) are also aware of this problem, describing it in detail in the [Unicode Technical Report #36](http://unicode.org/reports/tr36/) (UTR #36). Notably, they provide "[confusables.txt](https://www.unicode.org/Public/security/latest/confusables.txt)", a master list of all visually confusable characters in the Unicode spec. "confusables.txt" is handy because applications and libraries can use this list to determine if user-input contains any potentially misleading characters, or even to normalize a string. This library utilizes "confusables.txt" to do just that.

For more information, see [this talk from The Tarquin at DEFCON 2018](https://www.youtube.com/watch?v=Ec1OOiG4RMA) about some different kinds of Unicode homograph attacks. (Unfortunately, he recommends OCR as a solution, which is expensive, complicated, and a bit overboard for some use-cases.)

<br />
