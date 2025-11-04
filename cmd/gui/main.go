package main

import (
	_ "embed"
	"errors"
	"fmt"
	"image/color"
	_ "image/png"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Hussein-Mazeh/PasswordManager/internal/bio/toggle"
	pmsvc "github.com/Hussein-Mazeh/PasswordManager/internal/service"
)

func hasVault(dir string) bool {
	if _, err := os.Stat(filepath.Join(dir, "vault.db")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(dir, "header.json")); err == nil {
		return true
	}
	return false
}

func pickVaultDir() string {
	// 1) Prefer current working directory (good for `go run` from repo root)
	if wd, err := os.Getwd(); err == nil {
		if wdVault := filepath.Join(wd, "vault"); hasVault(wdVault) {
			return wdVault
		}
		if wdDev := filepath.Join(wd, "vault-dev"); hasVault(wdDev) {
			return wdDev
		}
	}
	// 2) Fall back to executable’s directory (good for packaged pm.exe)
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		if exeVault := filepath.Join(exeDir, "vault"); hasVault(exeVault) {
			return exeVault
		}
		if exeDev := filepath.Join(exeDir, "vault-dev"); hasVault(exeDev) {
			return exeDev
		}
	}
	// 3) Last resort: use CWD and let errors surface (you can add a file picker later)
	if wd, err := os.Getwd(); err == nil {
		return filepath.Join(wd, "vault")
	}
	return "vault"
}

var royalBlue = color.NRGBA{R: 18, G: 57, B: 166, A: 255}        // #1239A6 (deep royal)
var royalBlueLight = color.NRGBA{R: 224, G: 233, B: 255, A: 255} // soft tint
//go:embed assets/icon.jpeg
var iconBytes []byte

const autoLockAfter = 10 * time.Minute
const (
	defaultBiometricRPID   = "localhost"
	defaultBiometricOrigin = "https://localhost"
)

var (
	autoLockMu    sync.Mutex
	autoLockTimer *time.Timer
)

type accentTheme struct{ fyne.Theme }

func (a accentTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNamePrimary:
		return royalBlue
	case theme.ColorNameFocus:
		return color.NRGBA{R: royalBlue.R, G: royalBlue.G, B: royalBlue.B, A: 200}
	case theme.ColorNameHover:
		return color.NRGBA{R: royalBlue.R, G: royalBlue.G, B: royalBlue.B, A: 30}
	}
	return a.Theme.Color(n, v)
}

// blueHeader creates a royal-blue title bar with white text.
func blueHeader(title string) fyne.CanvasObject {
	bg := canvas.NewRectangle(royalBlue)
	bg.SetMinSize(fyne.NewSize(0, 36))
	t := canvas.NewText(title, color.White)
	t.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewMax(bg, container.NewPadded(t))
}

// sectionCard wraps a header + body with padding and a subtle border.
func sectionCard(title string, body fyne.CanvasObject) *fyne.Container {
	border := canvas.NewRectangle(color.NRGBA{R: 230, G: 230, B: 230, A: 255})
	// The border trick: put a light gray bg then inset actual content
	content := container.NewBorder(
		blueHeader(title), nil, nil, nil,
		container.NewPadded(body),
	)
	return container.NewMax(border, content)
}

// makePrimary makes a button follow the app accent (royal blue).
func makePrimary(btn *widget.Button) *widget.Button {
	btn.Importance = widget.HighImportance
	return btn
}

func main() {
	vaultDir := pickVaultDir()

	svc, err := pmsvc.New(vaultDir) // pass a **directory**, not a file
	if err != nil {
		log.Fatalf("open service at %s: %v", vaultDir, err)
	}
	defer svc.Close()

	a := app.New()
	// Load icon (path is from repo root when you run: go run ./cmd/gui)
	iconPath := "cmd/gui/assets/icon.jpeg"
	if data, err := os.ReadFile(iconPath); err == nil {
		res := fyne.NewStaticResource("icon.jpeg", data)
		a.SetIcon(res) // default for all windows
	}

	a.Settings().SetTheme(accentTheme{Theme: theme.LightTheme()})

	w := a.NewWindow("Password Manager")
	// Set on this window too (if icon loaded)
	if res := a.Icon(); res != nil {
		w.SetIcon(res)
	}

	w.Resize(fyne.NewSize(900, 600))

	root := container.NewMax()
	w.SetContent(root)

	stopAutoLock := func() {
		autoLockMu.Lock()
		if autoLockTimer != nil {
			autoLockTimer.Stop()
			autoLockTimer = nil
		}
		autoLockMu.Unlock()
	}
	var resetIdleTimer func()

	var showSetup func()
	var showLogin func()
	var showVault func()

	showSetup = func() {
		stopAutoLock()
		svc.Close()
		if s2, e := pmsvc.New(vaultDir); e == nil {
			svc = s2
		} else {
			dialog.ShowError(fmt.Errorf("reopen: %w", e), w)
			return
		}

		userEntry := widget.NewEntry()
		userEntry.SetPlaceHolder("Vault username")

		pass := widget.NewPasswordEntry()
		pass.SetPlaceHolder("Create master password")

		confirm := widget.NewPasswordEntry()
		confirm.SetPlaceHolder("Confirm master password")

		btnInit := makePrimary(widget.NewButton("Set Master Password", func() {
			username := strings.TrimSpace(userEntry.Text)
			pw := pass.Text
			conf := confirm.Text

			if username == "" {
				dialog.ShowInformation("Initialise Vault", "Provide a username for the vault header.", w)
				return
			}
			if pw == "" || conf == "" {
				dialog.ShowInformation("Initialise Vault", "Enter and confirm the master password.", w)
				return
			}
			if pw != conf {
				dialog.ShowInformation("Initialise Vault", "Passwords do not match.", w)
				return
			}

			needs, err := svc.NeedsMasterSetup()
			if err != nil {
				dialog.ShowError(fmt.Errorf("check vault state: %w", err), w)
				return
			}
			if !needs {
				dialog.ShowInformation("Initialise Vault", "Vault is already initialised. Please log in.", w)
				showLogin()
				return
			}

			if err := svc.SetMaster(username, pw); err != nil {
				dialog.ShowError(fmt.Errorf("set master: %w", err), w)
				return
			}

			pass.SetText("")
			confirm.SetText("")

			dialog.ShowInformation("Vault Ready", "Master password saved. Please log in.", w)
			showLogin()
		}))

		form := widget.NewForm(
			widget.NewFormItem("Username", userEntry),
			widget.NewFormItem("Master Password", pass),
			widget.NewFormItem("Confirm Password", confirm),
		)

		setupCard := widget.NewCard(
			"Initialise Vault",
			"This vault does not yet have a master password.",
			container.NewVBox(
				form,
				container.NewHBox(layout.NewSpacer(), btnInit),
			),
		)

		root.Objects = []fyne.CanvasObject{
			container.NewCenter(container.NewMax(container.NewPadded(setupCard))),
		}
		root.Refresh()
	}

	showLogin = func() {
		stopAutoLock()
		svc.Close()
		if s2, e := pmsvc.New(vaultDir); e == nil {
			svc = s2
		} else {
			dialog.ShowError(fmt.Errorf("reopen: %w", e), w)
			return
		}

		if needs, err := svc.NeedsMasterSetup(); err != nil {
			dialog.ShowError(fmt.Errorf("load vault header: %w", err), w)
			return
		} else if needs {
			showSetup()
			return
		}

		pass := widget.NewPasswordEntry()
		pass.SetPlaceHolder("Enter master password")

		btnUnlock := widget.NewButton("Unlock", func() {
			pw := strings.TrimSpace(pass.Text)
			if err := svc.Unlock(pw); err != nil {
				dialog.ShowError(fmt.Errorf("unlock failed: %w", err), w)
				return
			}
			pass.SetText("")
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
			showVault()
		})

		loginCard := widget.NewCard(
			"Vault Locked",
			"Please enter your master password",
			container.NewVBox(pass, btnUnlock),
		)
		root.Objects = []fyne.CanvasObject{
			container.NewCenter(container.NewMax(container.NewPadded(loginCard))),
		}
		root.Refresh()
	}

	showVault = func() {
		if resetIdleTimer != nil {
			resetIdleTimer()
		}

		withIdleReset := func(fn func()) func() {
			return func() {
				if resetIdleTimer != nil {
					resetIdleTimer()
				}
				fn()
			}
		}
		// --- Lock ---
		btnLock := widget.NewButton("Lock", withIdleReset(func() { showLogin() }))
		lockCard := sectionCard("Lock / Unlock", container.NewHBox(btnLock))

		// --- Change master (use a compact form) ---
		oldP := widget.NewPasswordEntry()
		oldP.SetPlaceHolder("Old master")
		oldP.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		newP := widget.NewPasswordEntry()
		newP.SetPlaceHolder("New master")
		newP.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		confirmP := widget.NewPasswordEntry()
		confirmP.SetPlaceHolder("Confirm new master")
		confirmP.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		changeForm := widget.NewForm(
			widget.NewFormItem("Old", oldP),
			widget.NewFormItem("New", newP),
			widget.NewFormItem("Confirm", confirmP),
		)
		btnChange := makePrimary(widget.NewButton("Change Master", withIdleReset(func() {
			oldTxt := strings.TrimSpace(oldP.Text)
			newTxt := strings.TrimSpace(newP.Text)
			confirmTxt := strings.TrimSpace(confirmP.Text)
			if oldTxt == "" || newTxt == "" || confirmTxt == "" {
				dialog.ShowInformation("Change Master", "Fill all password fields", w)
				return
			}
			if newTxt != confirmTxt {
				dialog.ShowInformation("Change Master", "New passwords do not match", w)
				return
			}
			if err := svc.ChangeMaster(oldTxt, newTxt); err != nil {
				dialog.ShowError(fmt.Errorf("change master: %w", err), w)
				return
			}
			oldP.SetText("")
			newP.SetText("")
			confirmP.SetText("")
			dialog.ShowInformation("Change Master", "Master changed", w)
		})))

		changeCard := sectionCard(
			"Change Master",
			container.NewVBox(changeForm, container.NewHBox(layout.NewSpacer(), btnChange)),
		)

		// --- Biometric toggle section ---
		statusValue := widget.NewLabel("Checking status…")
		statusValue.Wrapping = fyne.TextWrapWord

		var refreshBioStatus func()

		enableBioBtn := makePrimary(widget.NewButton("Enable", withIdleReset(func() {
			if err := svc.EnableBiometrics(defaultBiometricRPID, defaultBiometricOrigin); err != nil {
				if errors.Is(err, toggle.ErrUnsupported) {
					dialog.ShowInformation("Biometric Unlock", "Biometric unlock is only supported on macOS", w)
					return
				}
				dialog.ShowError(fmt.Errorf("enable biometrics: %w", err), w)
				return
			}
			dialog.ShowInformation("Biometric Unlock", "Touch ID enabled for this vault", w)
			if refreshBioStatus != nil {
				refreshBioStatus()
			}
		})))

		disableBioBtn := widget.NewButton("Disable", withIdleReset(func() {
			if err := svc.DisableBiometrics(); err != nil {
				if errors.Is(err, toggle.ErrUnsupported) {
					dialog.ShowInformation("Biometric Unlock", "Biometric unlock is only supported on macOS", w)
					return
				}
				dialog.ShowError(fmt.Errorf("disable biometrics: %w", err), w)
				return
			}
			dialog.ShowInformation("Biometric Unlock", "Touch ID disabled for this vault", w)
			if refreshBioStatus != nil {
				refreshBioStatus()
			}
		}))

		refreshBtn := widget.NewButton("Refresh Status", withIdleReset(func() {
			if refreshBioStatus != nil {
				refreshBioStatus()
			}
		}))

		bioForm := widget.NewForm(
			widget.NewFormItem("Status", statusValue),
		)

		refreshBioStatus = func() {
			state, err := svc.BiometricStatus()
			switch {
			case errors.Is(err, toggle.ErrUnsupported):
				statusValue.SetText("Biometric unlock is not supported on this platform.")
				enableBioBtn.Disable()
				disableBioBtn.Disable()
			case err != nil:
				statusValue.SetText(fmt.Sprintf("Status error: %v", err))
				enableBioBtn.Disable()
				disableBioBtn.Disable()
			default:
				enableBioBtn.Enable()
				if state.Enabled {
					statusValue.SetText("Enabled")
					disableBioBtn.Enable()
				} else {
					statusValue.SetText("Disabled")
					disableBioBtn.Disable()
				}
			}
		}

		bioCard := sectionCard(
			"Biometric Unlock",
			container.NewVBox(
				bioForm,
				container.NewHBox(
					refreshBtn,
					layout.NewSpacer(),
					disableBioBtn,
					enableBioBtn,
				),
			),
		)

		// --- Add credential (form) ---
		site := widget.NewEntry()
		site.SetPlaceHolder("example.com")
		site.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		user := widget.NewEntry()
		user.SetPlaceHolder("username")
		user.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		pass := widget.NewPasswordEntry()
		pass.SetPlaceHolder("password / secret")
		pass.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		addForm := widget.NewForm(
			widget.NewFormItem("Website", site),
			widget.NewFormItem("Username", user),
			widget.NewFormItem("Password", pass),
		)
		btnAdd := makePrimary(widget.NewButton("Add", withIdleReset(func() {
			if site.Text == "" || user.Text == "" || pass.Text == "" {
				dialog.ShowInformation("Add", "Fill website, username, and password", w)
				return
			}
			if err := svc.Add(site.Text, user.Text, pass.Text); err != nil {
				dialog.ShowError(fmt.Errorf("add: %w", err), w)
				return
			}
			site.SetText("")
			user.SetText("")
			pass.SetText("")
			dialog.ShowInformation("Add", "Credential saved", w)
		})))

		addCard := sectionCard(
			"Add Credential",
			container.NewVBox(addForm, container.NewHBox(layout.NewSpacer(), btnAdd)),
		)

		// --- Table (with widths + footer refresh button) ---

		table = widget.NewTable(
			func() (int, int) { return 1, 3 },
			func() fyne.CanvasObject {
				bg := canvas.NewRectangle(color.Transparent)
				hdr := canvas.NewText("", color.White) // header text (white)
				lbl := widget.NewLabel("")             // body text (default color)
				// pad the texts, keep bg under them
				return container.NewMax(
					bg,
					container.NewPadded(hdr),
					container.NewPadded(lbl),
				)
			},
			func(widget.TableCellID, fyne.CanvasObject) {},
		)

		// Scroll area that expands; give it some height
		tableScroll := container.NewVScroll(table)
		tableScroll.SetMinSize(fyne.NewSize(0, 420)) // taller list

		// Fit columns to window width (ID fixed, others proportional)
		setTableWidths := func() {
			// total width available inside the window (minus a little padding)
			avail := w.Canvas().Size().Width - 48
			if avail < 600 {
				avail = 600
			}
			idW := float32(110)
			rem := avail - idW
			siteW := rem * 0.62
			userW := rem * 0.38

			table.SetColumnWidth(0, idW)
			table.SetColumnWidth(1, siteW)
			table.SetColumnWidth(2, userW)
		}

		// Call once now…
		setTableWidths()

		// …and also whenever the window is resized
		w.Canvas().SetOnTypedKey(func(*fyne.KeyEvent) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		})
		w.SetOnClosed(func() {}) // keep a handle alive
		go func() {              // tiny watcher to refit widths on resize
			last := w.Canvas().Size()
			for {
				cur := w.Canvas().Size()
				if cur != last {
					last = cur
					setTableWidths()
					table.Refresh()
				}
				time.Sleep(120 * time.Millisecond)
			}
		}()

		btnRefresh := widget.NewButton("Refresh", withIdleReset(func() { refreshList(table, svc, w) }))
		controls := container.NewHBox(layout.NewSpacer(), btnRefresh)

		listCard := widget.NewCard(
			"Credentials", "",
			container.NewBorder(controls, nil, nil, nil,
				// NewMax makes the scroll (and thus table) use the whole card width
				container.NewMax(tableScroll),
			),
		)

		// --- Get / reveal (form) ---
		gSite := widget.NewEntry()
		gSite.SetPlaceHolder("example.com")
		gSite.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		gUser := widget.NewEntry()
		gUser.SetPlaceHolder("username")
		gUser.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		getForm := widget.NewForm(
			widget.NewFormItem("Website", gSite),
			widget.NewFormItem("Username", gUser),
		)
		btnGet := makePrimary(widget.NewButton("Get / Reveal", withIdleReset(func() {
			p, err := svc.Get(gSite.Text, gUser.Text)
			if err != nil {
				dialog.ShowError(fmt.Errorf("get: %w", err), w)
				return
			}

			pwdLbl := widget.NewLabel(p) // regular black text

			copyBtn := makePrimary(widget.NewButton("Copy", withIdleReset(func() {
				w.Clipboard().SetContent(p)
				dialog.ShowInformation("Copied", "Password copied to clipboard", w)
			})))

			dialog.NewCustom(
				"Password", "Close",
				container.NewVBox(
					widget.NewLabel("Password:"),
					pwdLbl,
					container.NewHBox(layout.NewSpacer(), copyBtn),
				),
				w,
			).Show()
		})))

		getCard := sectionCard(
			"Get Credential",
			container.NewVBox(getForm, container.NewHBox(layout.NewSpacer(), btnGet)),
		)

		// --- Update credential (form) ---
		uSite := widget.NewEntry()
		uSite.SetPlaceHolder("example.com")
		uSite.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		uUser := widget.NewEntry()
		uUser.SetPlaceHolder("username")
		uUser.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		uType := widget.NewEntry() // optional; leave blank to keep current
		uType.SetPlaceHolder("(optional) new type, e.g. password")
		uType.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		uPass := widget.NewPasswordEntry()
		uPass.SetPlaceHolder("new password / secret")
		uPass.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}

		updateForm := widget.NewForm(
			widget.NewFormItem("Website", uSite),
			widget.NewFormItem("Username", uUser),
			widget.NewFormItem("New Type", uType),
			widget.NewFormItem("New Password", uPass),
		)

		btnUpdate := makePrimary(widget.NewButton("Update", withIdleReset(func() {
			site := strings.TrimSpace(uSite.Text)
			user := strings.TrimSpace(uUser.Text)
			typ := strings.TrimSpace(uType.Text) // may be ""
			pwd := uPass.Text

			if site == "" || user == "" || pwd == "" {
				dialog.ShowInformation("Update", "Fill website, username, and new password (type is optional)", w)
				return
			}
			if err := svc.Update(site, user, typ, pwd); err != nil {
				dialog.ShowError(fmt.Errorf("update: %w", err), w)
				return
			}
			uPass.SetText("") // don’t keep secrets in the field
			dialog.ShowInformation("Update", "Credential updated", w)
			refreshList(table, svc, w)
		})))

		updateHint := widget.NewLabel(`Leave "New Type" blank to keep the current type.`)

		updateCard := sectionCard(
			"Update Credential",
			container.NewVBox(
				updateForm,
				updateHint,
				container.NewHBox(layout.NewSpacer(), btnUpdate),
			),
		)

		// --- Delete credential (form) ---
		dSite := widget.NewEntry()
		dSite.SetPlaceHolder("example.com")
		dSite.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}
		dUser := widget.NewEntry()
		dUser.SetPlaceHolder("username")
		dUser.OnChanged = func(string) {
			if resetIdleTimer != nil {
				resetIdleTimer()
			}
		}

		delForm := widget.NewForm(
			widget.NewFormItem("Website", dSite),
			widget.NewFormItem("Username", dUser),
		)

		btnDelete := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), withIdleReset(func() {
			site := strings.TrimSpace(dSite.Text)
			user := strings.TrimSpace(dUser.Text)
			if site == "" || user == "" {
				dialog.ShowInformation("Delete", "Fill website and username", w)
				return
			}
			dialog.NewConfirm(
				"Delete",
				fmt.Sprintf("Delete %s / %s ?", site, user),
				func(ok bool) {
					if !ok {
						return
					}
					if resetIdleTimer != nil {
						resetIdleTimer()
					}
					if err := svc.Delete(site, user); err != nil {
						dialog.ShowError(fmt.Errorf("delete: %w", err), w)
						return
					}
					dialog.ShowInformation("Delete", "Credential deleted", w)
					refreshList(table, svc, w)
				},
				w,
			).Show()
		}))

		deleteCard := sectionCard(
			"Delete Credential",
			container.NewVBox(
				delForm,
				container.NewHBox(layout.NewSpacer(), btnDelete),
			),
		)

		// --- Stack sections with padding + separators ---
		content := container.NewVBox(
			container.NewPadded(lockCard),
			widget.NewSeparator(),
			container.NewPadded(changeCard),
			widget.NewSeparator(),
			container.NewPadded(bioCard),
			widget.NewSeparator(),
			container.NewPadded(addCard),
			widget.NewSeparator(),
			container.NewPadded(listCard),
			widget.NewSeparator(),
			container.NewPadded(getCard),

			// ↓↓↓ Add these lines ↓↓↓
			widget.NewSeparator(),
			container.NewPadded(updateCard),
			widget.NewSeparator(),
			container.NewPadded(deleteCard),
		)

		root.Objects = []fyne.CanvasObject{
			container.NewPadded(container.NewVScroll(content)), // outer padding + scroll
		}
		root.Refresh()

		// populate status at the end
		refreshBioStatus()
		refreshList(table, svc, w)
	}

	resetIdleTimer = func() {
		autoLockMu.Lock()
		if autoLockTimer != nil {
			autoLockTimer.Stop()
		}
		autoLockTimer = time.AfterFunc(autoLockAfter, func() {
			fyne.Do(func() {
				autoLockMu.Lock()
				autoLockTimer = nil
				autoLockMu.Unlock()
				if !svc.IsUnlocked() {
					return
				}
				dialog.ShowInformation("Session Locked", "No activity for 10 minutes; vault locked.", w)
				showLogin()
			})
		})
		autoLockMu.Unlock()
	}

	initialNeedsSetup, err := svc.NeedsMasterSetup()
	if err != nil {
		log.Fatalf("inspect vault header: %v", err)
	}
	if initialNeedsSetup {
		showSetup()
	} else {
		showLogin()
	}
	w.ShowAndRun()
}

var table *widget.Table

func refreshList(t *widget.Table, svc *pmsvc.Service, w fyne.Window) {
	items, err := svc.List()
	if err != nil {
		dialog.ShowError(fmt.Errorf("list: %w", err), w)
		return
	}

	// rows = header + items (at least 1 header row)
	rows := len(items) + 1
	t.Length = func() (int, int) { return rows, 3 }

	t.UpdateCell = func(id widget.TableCellID, obj fyne.CanvasObject) {
		max := obj.(*fyne.Container)
		bg := max.Objects[0].(*canvas.Rectangle)
		// padded(hdr) is index 1, padded(lbl) is index 2
		hdr := max.Objects[1].(*fyne.Container).Objects[0].(*canvas.Text)
		lbl := max.Objects[2].(*fyne.Container).Objects[0].(*widget.Label)

		if id.Row == 0 { // header
			// header visuals
			bg.FillColor = royalBlue
			bg.Show()

			hdr.TextSize = theme.TextSize()
			hdr.TextStyle = fyne.TextStyle{Bold: true}
			hdr.Color = color.White
			lbl.Hide()
			hdr.Show()

			switch id.Col {
			case 0:
				hdr.Text = "ID"
			case 1:
				hdr.Text = "Website"
			case 2:
				hdr.Text = "Username"
			}
			hdr.Refresh()
			return
		}

		// body rows
		r := items[id.Row-1]
		hdr.Hide()
		lbl.Show()

		// soft zebra striping for readability
		if id.Row%2 == 0 {
			bg.FillColor = royalBlueLight
			bg.Show()
		} else {
			bg.FillColor = color.Transparent
			bg.Hide()
		}

		lbl.TextStyle = fyne.TextStyle{} // normal weight
		switch id.Col {
		case 0:
			lbl.SetText(fmt.Sprintf("%d", r.ID))
		case 1:
			lbl.SetText(r.Website)
		case 2:
			lbl.SetText(r.Username)
		}
	}

	// Make header/rows taller for readability
	t.SetRowHeight(0, 30)
	for r := 1; r < rows; r++ {
		t.SetRowHeight(r, 28)
	}

	t.Refresh()
}
