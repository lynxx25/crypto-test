FROM python:3

RUN useradd -ms /bin/bash test

USER test
WORKDIR /home/test
RUN mkdir logs

COPY --chown=test src .
COPY --chown=test test test

RUN python -m pip install --upgrade pip
RUN pip install requests behave pyotp pprintjson pytest mockito --no-warn-script-location

RUN cd test; ../.local/bin/pytest

CMD [ ".local/bin/behave" ]
