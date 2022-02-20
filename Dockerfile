FROM python:3

RUN useradd -ms /bin/bash test

USER test
WORKDIR /home/test
RUN mkdir logs

COPY --chown=test src/crypto_test.py .

RUN python -m pip install --upgrade pip
RUN pip install behave pyotp --no-warn-script-location

CMD [ "python", "crypto_test.py" ]
