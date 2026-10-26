# Disclaimer — Authorized Use Only

This project is a web interface and orchestration layer built around
**PRET (Printer Exploitation Toolkit)**. It is intended for:

- **Authorized security assessment** of printers and print infrastructure
  you own or have explicit, documented written permission to test.
- **Educational / cyber-learning use** — e.g. as a lab tool for a printer
  networking / security course, run against lab equipment on an isolated
  or clearly-scoped network.
- **Security research and defensive study** of printer protocol
  weaknesses, so defenders can recognize and remediate them.

## It is not intended for, and must not be used for

- Testing, scanning, or connecting to any printer, print server, or
  network you do not own and do not have explicit written authorization
  to assess.
- Any use outside the network scope you have explicitly configured and
  authorized in this application's own settings (see
  `pret-web-ui-docs/05-SECURITY-ARCHITECTURE.md`).
- Any destructive action against production systems without a documented
  maintenance window and stakeholder sign-off.

## No warranty

Consistent with upstream PRET's own disclaimer (reproduced below) and the
GPLv2 license this project is distributed under: this software is
provided "AS IS," without warranty of any kind, express or implied,
including but not limited to the warranties of merchantability, fitness
for a particular purpose, and non-infringement. In no event shall the
authors or copyright holders be liable for any claim, damages, or other
liability arising from, out of, or in connection with the software or the
use or other dealings in the software.

## Upstream PRET disclaimer (reproduced verbatim from `pret/DISCLAIMER.md`)

```
***********************************************************
USE AT YOUR OWN RISK FOR ACADEMIC & NON-MALICIOUS PURPOSES.
***********************************************************

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
COPYRIGHT HOLDER OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
```

## Operator responsibility

Before pointing this tool at any device: confirm you have the legal right
and explicit authorization to do so, configure the authorized-subnet
allow-list in Settings to match only that scope, and keep Safe Mode on
unless you specifically intend to run a state-changing operation with
sign-off to do so.
