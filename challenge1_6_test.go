package crp_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/delabroj/crp"
	"github.com/stretchr/testify/require"
)

func TestHammingDistance(t *testing.T) {
	cases := []struct {
		b1          []byte
		b2          []byte
		expDistance int
	}{
		{
			b1:          crp.Bytes("this is a test"),
			b2:          crp.Bytes("wokka wokka!!!"),
			expDistance: 37,
		},
	}

	for _, tc := range cases {
		distance, err := crp.HammingDistance(tc.b1, tc.b2)
		require.Nil(t, err)
		require.Equal(t, tc.expDistance, distance)
	}
}

func _TestFindXORKeyLength(t *testing.T) {
	cases := []struct {
		plaintext crp.Bytes
	}{
		{
			plaintext: crp.Bytes(loremIpsum),
		},
	}

	longKey := crp.Bytes("123456789009876543211234567890098765432a")

	for _, tc := range cases {
		for i := 2; i <= 40; i++ {
			cipher, err := tc.plaintext.HexXOR(longKey[:i])
			require.Nil(t, err)
			keys, err := cipher.FindXORKeyLength()
			require.Nil(t, err)
			var keyLengthFound bool
			for _, v := range keys {
				if v == i {
					keyLengthFound = true
				}
			}
			require.True(t, keyLengthFound, fmt.Sprintf("i: %v, keys: %v", i, keys))
		}
	}
}

func TestCrackRepeatingXOREncryption(t *testing.T) {
	rawCipherBase64, err := ioutil.ReadFile("./challenge1_6.txt")
	require.Nil(t, err)
	cipherBase64 := crp.Base64(strings.Replace(string(rawCipherBase64), "\n", "", -1))

	cipherPT, err := cipherBase64.Decode()
	require.Nil(t, err)

	keyLengths, err := cipherPT.FindXORKeyLength()
	require.Nil(t, err)

	key, err := cipherPT.FindXORKey(keyLengths[0])
	require.Nil(t, err)
	log.Printf(`Challenge 1.6 key: "%v"`, string(key))

	plaintext, err := cipherPT.HexXOR(key)
	require.Nil(t, err)
	// log.Printf("Challenge 1.6 message:\n%v", string(plaintext))
	log.Printf("Challenge 1.6 message fragment:\n%v...", string(plaintext[:100]))
}

var loremIpsum = `Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum venenatis luctus semper. Praesent eu magna lobortis, dictum sem sed, vulputate magna. Praesent id orci tempor, placerat leo nec, blandit massa. Vivamus venenatis facilisis sapien, vitae vulputate augue pharetra id. Proin et finibus orci. Duis facilisis tempor mi, nec sodales ipsum tincidunt lacinia. Ut at fringilla elit. Integer velit nibh, pulvinar ac facilisis a, rutrum ut sem. Nulla venenatis nisl ac consectetur malesuada. Aenean diam purus, facilisis sit amet hendrerit nec, porttitor ut nunc. Phasellus a sollicitudin neque. Curabitur eu sodales arcu.

Nunc id auctor est, eget dapibus arcu. Vestibulum eget ipsum vel ligula iaculis volutpat sit amet quis ligula. Ut ultricies laoreet ligula. Cras nulla nisi, accumsan sit amet sollicitudin nec, cursus ac risus. Quisque gravida nibh sed eleifend tristique. Aliquam laoreet ullamcorper ex, eget vulputate ex vehicula vehicula. Cras fermentum rhoncus tellus id pretium. Praesent vel faucibus ex, sed laoreet elit. Morbi non pretium dui, id bibendum lorem. Morbi lacinia volutpat rhoncus. Suspendisse ornare nulla non vestibulum ullamcorper. Vestibulum metus justo, ullamcorper ac est a, laoreet lobortis orci.

Sed eu aliquam turpis. Donec sit amet velit sit amet nibh hendrerit efficitur sit amet sed sapien. Aenean sagittis a ante a porttitor. Suspendisse et varius augue. Donec eget eros eget neque commodo consectetur. Curabitur rutrum in quam ac tempor. Mauris varius purus nec ante volutpat, quis placerat nunc sodales. Donec ac sodales ante, vel vulputate arcu. Praesent maximus purus finibus nisi pharetra, sed fermentum neque finibus.

Etiam semper, enim a iaculis eleifend, quam felis tincidunt mi, sit amet egestas dolor quam ut turpis. Mauris vel libero tempor velit tristique fringilla. Sed nec ornare lacus. Curabitur et purus ac sapien accumsan accumsan. Duis at accumsan dui. Integer congue non sem tincidunt vestibulum. Proin pretium sapien eget felis pharetra hendrerit. Duis ligula libero, finibus nec velit id, finibus iaculis lacus. Aenean vel eros et ipsum viverra congue. Mauris vel placerat risus, in suscipit sapien. Cras lacinia aliquet interdum.

Mauris congue sit amet sem ac tempor. Nullam ligula purus, pretium eu scelerisque vitae, condimentum non arcu. Curabitur tincidunt sapien ac scelerisque finibus. Nam vestibulum tortor ac condimentum laoreet. Vivamus tempor ac lorem in viverra. Vivamus eu elit ultrices, aliquam massa quis, scelerisque neque. Nam interdum enim eget maximus vehicula. Vestibulum euismod massa scelerisque, varius elit at, malesuada nisi. Ut fermentum, lorem ut finibus venenatis, neque mauris semper neque, eget luctus lorem nulla at nulla. Suspendisse tempus ipsum felis, at suscipit ipsum sagittis vitae.

Suspendisse dapibus mi id rutrum convallis. Praesent interdum ultricies lectus, at mattis leo feugiat et. Phasellus non sem cursus, mattis risus vitae, ultricies ipsum. Etiam at convallis lorem. Nulla leo nisl, faucibus vel augue in, tristique efficitur nisi. Nam et elit nunc. Donec magna lacus, commodo sit amet finibus nec, vulputate eget magna.

Sed lobortis augue a mi interdum facilisis. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Nullam viverra nisi a posuere egestas. Praesent vel augue sed turpis facilisis pharetra. Sed faucibus non nulla vitae consequat. Integer dictum sagittis aliquet. Quisque est lorem, venenatis bibendum euismod non, malesuada nec dolor. Praesent eu enim vestibulum turpis tristique faucibus a sit amet ante.

Fusce mollis dolor tortor, vel bibendum eros pellentesque non. Etiam turpis ligula, dictum sed euismod id, placerat quis urna. Duis fringilla lectus leo, ac rutrum lacus accumsan et. Nunc sagittis urna vel sem ultricies sagittis. Mauris scelerisque dui id leo tempus, ut rhoncus sem commodo. Quisque et neque pretium, porttitor dui faucibus, auctor massa. Quisque nec neque sed lorem auctor dictum.

Mauris nec porta nisl. Nullam molestie porta porta. Class aptent taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos. Vestibulum ac ipsum orci. Etiam et erat dignissim, sodales dolor vitae, congue eros. Aenean in urna magna. Integer nec justo sed dolor aliquam volutpat. Nam quis maximus quam, gravida auctor enim. Fusce porttitor ullamcorper tellus, eu porta dui finibus non. Sed orci nisi, feugiat a mi vel, tempor euismod tellus. Sed sed mi et neque ornare pretium.

Maecenas in nisi nunc. Aliquam vestibulum tincidunt malesuada. Sed nec magna at eros interdum hendrerit. Nam ut tincidunt massa. Donec vel tellus sit amet nulla mattis suscipit eget volutpat ipsum. Fusce id ante id erat suscipit elementum. Integer quis justo bibendum, rhoncus massa et, tristique magna. Suspendisse lobortis aliquam odio, accumsan rhoncus neque pharetra vitae. Nullam ac diam quis nulla suscipit luctus sed ut quam. Sed sagittis ullamcorper commodo. Fusce congue fermentum metus dapibus vulputate. Vivamus sed aliquet quam, nec gravida arcu. Mauris vestibulum finibus placerat. Nulla facilisi.

Quisque pharetra vulputate metus mattis luctus. Ut id aliquam velit. Sed sagittis sed nisl nec pulvinar. Curabitur luctus metus faucibus, sagittis ex porta, placerat neque. Curabitur commodo fringilla justo consequat iaculis. Aliquam iaculis nibh sit amet felis posuere pulvinar eu quis est. Cras facilisis dui rhoncus, ultricies tellus sed, porttitor tortor. Phasellus eu laoreet risus. Curabitur imperdiet dignissim cursus. Sed in mollis augue. Aliquam erat volutpat. Vivamus mi sem, cursus ac vestibulum id, commodo vel enim. Maecenas scelerisque viverra dui. Donec vel arcu at enim tempus dictum ornare interdum felis. Suspendisse vel diam tempus, volutpat ante non, semper magna. Curabitur sapien libero, vestibulum vitae cursus a, feugiat nec nibh.

Etiam scelerisque leo ac quam imperdiet auctor. Pellentesque mollis orci urna, ac imperdiet augue blandit et. Praesent ac sodales urna, vitae dictum metus. Ut placerat libero ultricies odio ornare convallis. Maecenas pulvinar mauris vitae tristique congue. Quisque pellentesque mattis ante eget semper. Proin ex mi, ultrices sit amet sem et, aliquet egestas purus. Donec dictum semper est eget sollicitudin. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Cras vitae gravida elit, ut consectetur nibh. Integer placerat tempor nulla, sed vehicula mi consectetur sed. Maecenas dolor nulla, rutrum at ligula sed, vestibulum auctor nunc. Sed nulla libero, efficitur quis nisl convallis, maximus consectetur magna. Aliquam gravida enim rutrum erat fringilla porta et eget diam. Aenean libero est, iaculis eget elementum at, interdum non lorem. Phasellus sit amet ullamcorper magna, vel auctor velit.

Nulla ac leo nec nisl blandit dignissim. Morbi bibendum blandit lacus, sit amet viverra mi ullamcorper quis. Donec dapibus rutrum imperdiet. Quisque lectus ante, semper at egestas sed, placerat sodales ante. Mauris ut mi ac arcu finibus porta. Nullam ullamcorper in neque non laoreet. Etiam ut feugiat massa, nec rhoncus nulla. Vestibulum ultrices ut ante hendrerit aliquam. Nam suscipit, nulla sit amet lobortis tincidunt, ex felis ornare ipsum, ac facilisis ante erat ut sapien. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Donec vulputate egestas dapibus.

Donec pellentesque ex id dolor imperdiet, tincidunt venenatis erat interdum. Suspendisse potenti. Phasellus sagittis blandit enim sit amet pulvinar. Donec interdum leo turpis, sit amet porta enim tincidunt eget. Curabitur eget facilisis dolor, quis dictum metus. Maecenas orci felis, sagittis vel vestibulum sit amet, volutpat interdum turpis. Sed a erat eget felis euismod dapibus nec eu metus. Phasellus sapien enim, auctor a hendrerit at, gravida vel metus. Proin vehicula euismod maximus. Duis nisl justo, vehicula sed erat porttitor, vestibulum molestie nibh. In sodales, sem lobortis dignissim egestas, tortor justo congue magna, non tincidunt nisi ex sodales diam. Ut congue tempus nibh, in bibendum nisi congue et.

Suspendisse blandit vulputate lorem et fermentum. Vivamus congue aliquet mattis. Fusce viverra sem a hendrerit sagittis. Ut quis tortor venenatis, vestibulum sem ac, rhoncus massa. Vestibulum efficitur iaculis eros, vitae tincidunt tortor tempor vel. Donec nec feugiat arcu, sed vehicula justo. Sed feugiat nunc ac urna ultricies, eget pellentesque dolor fermentum. Etiam eget consequat quam, vel porttitor tortor. Suspendisse metus arcu, pulvinar in finibus et, mollis id velit.

Mauris ut ante eros. Morbi nec laoreet augue. Maecenas vehicula convallis lobortis. Fusce a risus interdum, laoreet mauris a, lacinia leo. Interdum et malesuada fames ac ante ipsum primis in faucibus. Suspendisse sit amet risus sodales, malesuada ipsum vitae, tempor nisl. Vivamus eleifend mi et velit vestibulum, non tristique urna pharetra. Duis eu augue auctor, dapibus dui sed, fermentum eros.

Nullam nec interdum libero. Mauris facilisis vel leo quis vestibulum. Donec dui eros, pretium et tristique quis, blandit ut magna. Nunc in euismod ligula. Sed non est a nisl tempor aliquet. Pellentesque et purus dui. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Suspendisse vitae rhoncus massa. Mauris at risus nec orci condimentum pulvinar. Integer sit amet mi ac purus fringilla imperdiet ac vel risus. Quisque tempor molestie leo id congue.

Maecenas quis tellus pretium, cursus enim et, fermentum tortor. Aliquam tincidunt massa id egestas luctus. Fusce quis blandit turpis. Donec maximus nunc orci, nec ultricies lacus fermentum quis. Donec eu tortor ac elit ornare consequat. Mauris et sem sem. Sed sagittis faucibus felis quis mattis. Vestibulum ac iaculis quam. Phasellus id velit vulputate, accumsan lacus eu, luctus magna. Donec ullamcorper lobortis diam. Nullam id dolor suscipit elit tristique imperdiet. Cras eleifend urna vel tempus condimentum. Pellentesque id varius metus.`
