"""Lightweight jupyter client for the RSP.  It is a stripped-down version
of mobu's jupyterhubclient."""

from __future__ import annotations

import asyncio
from aiohttp import ClientSession, ClientResponse, ClientWebSocketResponse

from contextlib import contextmanager

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from typing import Any, Dict, Union
    from aiohttp.client import _RequestContextManager, _WSRequestContextManager

from http.cookies import BaseCookie
from uuid import uuid4

# Taken directly from mobu
class JupyterClientSession:
    """Wrapper around `aiohttp.ClientSession` using token authentication.

    Unfortunately, aioresponses does not capture headers set on the session
    instead of with each individual call, which means that we can't see the
    token and thus determine what user we should interact with in the test
    suite.  Work around this with this wrapper class around
    `aiohttp.ClientSession` that just adds the token header to every call.

    Parameters
    ----------
    session : `aiohttp.ClientSession`
        The session to wrap.
    gafaelfawr_token : `str`
        The token to send that gets us through the ingress auth
    user_token : `str`
        The Hub-to-Lab token that tells the lab we're authorized
    """

    def __init__(
        self,
        session: ClientSession,
        gafaelfawr_token: str,
        user_token: str = "",
    ) -> None:
        self._session = session
        self.log = logging.getLogger(__name__)
        self._gafaelfawr_token = gafaelfawr_token
        self._user_token = user_token

    async def close(self) -> None:
        await self._session.close()

    def request(
        self, method: str, url: str, **kwargs: Any
    ) -> _RequestContextManager:
        headers = CIMultiDict()
        if "headers" in kwargs:
            headers.update(kwargs["headers"])
        headers["Authorization"] = f"Bearer {self.gafaelfawr_token}"
        if self.user_token:
            headers.add("Authorization", f"token {self.user_token}")
        kwargs["headers"] = headers
        self.log.info(
            "JupyterClientSession request: "
            + f"headers: {headers} | "
            + f"{method} {url} | "
            + f"kwargs {kwargs}"
        )
        return self._session.request(method, url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("delete", url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("get", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _RequestContextManager:
        return self.request("post", url, **kwargs)

    def ws_connect(
        self, *args: Any, **kwargs: Any
    ) -> _WSRequestContextManager:
        if "headers" not in kwargs:
            kwargs["headers"] = CIMultiDict()
        kwargs["headers"]["Authorization"] = f"Bearer {self.gafaelfawr_token}"
        if self._user_token:
            kwargs["headers"].add("Authorization", f"Token {self.user_token}")
        return self._session.ws_connect(*args, **kwargs)

    
class JupyterClient:
    """Slightly-simplified-from-mobu client for doing stuff with an RSP
    Jupyter instance."""
    __ansi_reg_exp = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]")

    @classmethod
    def _ansi_escape(cls, line: str) -> str:
        return cls.__ansi_reg_exp.sub("", line)
    
    def __init__(self, config: Dict[str, Any], base_url: str,
                 gafaelfawr_token:str) -> None:
        self._set_log()
        self.config = config
        # Because we are using a pre-supplied user token, we never communicate
        #  to anything outside of /nb
        self.hub_url = base_url + "/nb/hub/"
        self.gafaelfawr_token = gafaelfawr_token
        self.user_token: str = ""
        userconfig = config.get("user", {})
        self.username = userconfig.get("username", "test01")
        self.uid = userconfig.get("uid", 10001)
        self.user_url: str = f"{base_url}/nb/user/{self.username}"
        self._set_session()
        self.lab_session_id:str = ""
        self.websocket: Optional[ClientWebSocketResponse] = None
        self.code = userconfig.get("code", "print(2+2)\n")

    def _set_log(self):
        self.log=logging.getlogger(__name__)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        fmtr = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s '
                                 +'- %(message)s')
        ch.setFormatter(formatter)
        self.log.addHandler(ch)
        self.log.debug("Initializing JupyterClient")

    def _set_options_form(self):
        rec = "registry.hub.docker.com/lsstsqre/sciplat-lab:recommended"
        default_form = {
            "image": rec,
            "image_list": (f"{rec}|Recommended|"),
            "image_dropdown": "use_image_from_dropdown",
            "size": "Small"
        }
        self.jupyter_options_form = self.config.get("jupyter_options_form",
                                                    default_form)
        
    def _set_session(self):
        xsrftoken = "".join(
            random.choices(string.ascii_uppercase + string.digits, k=16))
        headers = {"x-xsrftoken": xsrftoken}
        aio_session = ClientSession(headers=headers, raise_for_status=True)
        aio_session.cookie_jar.update_cookies(BaseCookie({"_xsrf": xsrftoken}))
        # User token will be filled in after hub login
        self.session = JupyterClientSession(
            aio_session, log, gafaelfawr_token=user.token, user_token=""
        )

        @contextmanager
        def logged(label):
            self.log.info(f"Entering \"{label}\"")
            try:
                yield
            finally:
                self.log.info("Leaving \"{label}\"")
        
        async def close(self) -> None:
            with logged("close"):
                if self.lab_session_id:
                    self.delete_lab_session()
                await self.session.close()

        async def hub_login(self) -> None:
            with logged("hub_login"):
                r = await self.session.get(f"{self.hub_url}login")
                if r.status != 200:
                    await self._raise_from_response(
                        f"Unexpected status {r.status} in hub_login:", r)

    async def update_user_token(self) -> None:
        with logged("update_user_token"):
            headers = {"Referer": f"{self.hub_url}home"}
            r = self.session.post(
                f"{self.user.url}api/users/{self.user.username}/tokens",
                headers=headers)
            if r.status != 200:
                await self._raise_from_response(
                    "Unexpected status {r.status} getting user token", r)
            response = await r.json()
            # This blows up stuff
            #self.session._user_token = response["token"]
            self.log.warning(
                f"Got user token {response['token']}; not updating")

    async def ensure_lab(self) -> None:
        with logged("ensure_lab"):
            running = await self.is_lab_running()
            if running:
                await self.lab_login()
            else:
                await self.spawn_lab()

    async def is_lab_running(self) -> bool:
        with logged("is_lab_running"):
            r = await self.session.get(self.hub_url)
            if r.status != 200:
                self.log.error(f"Unexpected status {r.status} from {r.url}")
            spawn_url = f"{self.hub_url}spawn"
            self.log.info(f"{hub_url} redirected to {r.url}")
            if str(r.url) == spawn_url:
                return False
        return True

    async def lab_login(self) -> None:
        with logged("lab_login"):
            self.log.info("Logging into lab")
            lab_url = f"{self.user.url}/lab"
            r = await self.session.get(lab_url)
            if r.status != 200:
                await self._raise_from_response(
                    "Unexpected status {r.status} logging into lab", r)

    async def spawn_lab(self) -> None:
        with logged("spawn_lab"):
            spawn_url = f"{self.hub_url}spawn"
            pending_url = f"{self.hub_url}spawn-pending/{self.user.username}"
            lab_url = f"{self.user_url}/lab"

            # DM-23864: Do a get on the spawn URL even if I don't have to.
            r = await self.session.get(spawn_url)
            await r.text()

            r = await self.session.post(
                spawn_url, data=self.jupyter_options_form,
                allow_redirects=False
            )
            if r.status != 302:
                await self._raise_from_response("Spawn did not redirect", r)
            redirect_url = (
                f"{self.hub_url}hub/spawn-pending/{self.user.username}"
            )
            if r.headers["Location"] != redirect_url:
                await self._raise_from_response(
                    "Spawn did not redirect to pending", r)

            # Jupyterlab will give up a spawn after 900 seconds, so don't
            # wait longer than that.
            max_poll_secs = 900
            poll_interval = 5
            retries = max_poll_secs / poll_interval

            while retries > 0:
                r = await self.session.get(pending_url)
                if str(r.url) == lab_url:
                    self.log.info(f"Lab spawned, redirected to {r.url}")
                    return

                self.log.info(f"Still waiting for lab to spawn [{r.status}]")
                retries -= 1
                await asyncio.sleep(poll_interval)

            raise Exception("Giving up waiting for lab to spawn!")


    async def delete_lab(self) -> None:
        with logged("delete_lab"):
            headers = {"Referer": f"{self.hub_url}home"}
            server_url = (
                f"{self.hub_url}api/users/{self.user.username}/server"
            )
            self.log.info(
                f"Deleting lab for {self.user.username} at {server_url}")
            r = await self.session.delete(server_url, headers=headers)
            if r.status not in (200, 202, 204):
                await self._raise_from_response(
                    f"Unexpected status {r.status} deleting lab", r)

    async def create_lab_session(
        self, kernel_name: str = "LSST"
    ) -> None:
        with logged("create_lab_session"):
            session_url = (
                f"{self.user.url}api/sessions"
            )
            body = {
                "kernel": {"name": kernel_name},
                "name": "(no notebook)",
                "path": uuid4().hex,  # Hope it's arbitrary!
                "type": "console",  # Possibly "notebook"
            }
            r = await self.session.post(session_url, json=body)
            if r.status != 201:
                await self._raise_error(
                    "Unexpected status {r.status} creating kernel", r)
                response = await r.json()
                session_id = response["id"]
                kernel_id = response["kernel"]["id"]
                self.log.info(
                    f"Connecting WebSocket for session {session_id}"
                    + f", kernel {kernel_id}"
                )
                self.websocket = await self._websocket_connect(kernel_id)
                self.lab_session_id = session_id

    async def delete_lab_session(self) -> None:
        with logged("delete_lab_session"):
            if not self.lab_session_id:
                self.log.error("No lab session to delete!")
                return  # Should we raise an exception?
            session_url = f"{self.user_url}api/sessions/{self.lab_session_id}"
            r = await self.session.delete(session_url)
            if r.status != 204:
                self.log.warning(f"Delete lab session {session_id}: {r}")
            self.lab_session_id = ""
            if not self.websocket:
                self.log.error("No WebSocket to close!")
                return
            self.log.info(f"Closing WebSocket {self.websocket}")
            await self.websocket.close()
            self.websocket = None
            return

    async def run_python(self) -> str:
        with logged("run_python"):
            if not self.lab_session_id:
                raise Exception("No Lab session established!")
            msg_id = uuid4().hex
            msg = {
                "header": {
                    "username": self.username,
                    "version": "5.0",
                    "session": self.lab_session_id,
                    "msg_id": msg_id,
                    "msg_type": "execute_request",
                    "date": datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                },
                "parent_header": {},
                "channel": "shell",
                "content": {
                    "code": self.code,
                    "silent": False,
                    "store_history": False,
                    "user_expressions": {},
                    "allow_stdin": False,
                },
                "metadata": {},
                "buffers": {},
            }

            self.log.debug(f"Code execution header: {msg['header']}")
            self.log.debug(f"Sending code execution message: {msg}")
            await self.websocket.send_json(msg)
            while True:
                r = await self.websocket.receive_json()
                self.log.debug(f"Received kernel message: {r}")
                msg_type = r["msg_type"]
                if msg_type == "error":
                    error_message = "".join(r["content"]["traceback"])
                    raise NotebookException(self._ansi_escape(error_message))
                elif (
                    msg_type == "stream"
                        and msg_id == r["parent_header"]["msg_id"]
                ):
                    return r["content"]["text"]
                elif msg_type == "execute_reply":
                    status = r["content"]["status"]
                    if status == "ok":
                        return ""
                    else:
                        raise NotebookException(
                            f"Error content status is {status}"
                        )

    async def _websocket_connect(
        self, kernel_id: str
    ) -> ClientWebSocketResponse:
        with logged("_websocket_connect"):
            ws_url = f"{self.user_url}api/kernels/{kernel_id}/channels"
            self.log.info(f"Attempting WebSocket connection to {ws_url}")
            return await self.session.ws_connect(ws_url)

    async def _raise_from_response(self, msg: str, r: ClientResponse) -> None:
        raise Exception(
            f"{msg}: Response: {r.status} [{r.reason}] "
            + f"{r.method} {r.url} (headers {r.headers}) "
            + f"(cookies {r.cookies}) -> {await r.content.read()}"
        )
